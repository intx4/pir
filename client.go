package pir

import (
	"errors"
	"fmt"
	"github.com/tuneinsight/lattigo/v4/bfv"
	"github.com/tuneinsight/lattigo/v4/rlwe"
	"log"
	"math"
	"math/rand"
	"pir/settings"
	"pir/utils"
)

type PIRClient struct {
	SetsOfBox map[string]*settings.HeBox
	Id        string
}

func NewPirClient(setsOfParams []bfv.Parameters, id string) *PIRClient {
	client := new(PIRClient)
	client.Id = id
	client.SetsOfBox = make(map[string]*settings.HeBox)
	for _, params := range setsOfParams {
		b, _ := settings.NewHeBox(params)
		client.SetsOfBox[utils.FormatParams(params)] = b
	}
	return client
}

// Creates a new profile to be sent to server
func (PC *PIRClient) GenProfile() *settings.PIRProfile {
	pp := &settings.PIRProfile{ClientId: PC.Id, CryptoParams: make([]settings.PIRCryptoParams, len(PC.SetsOfBox))}
	i := 0
	for k, b := range PC.SetsOfBox {
		pp.CryptoParams[i] = settings.PIRCryptoParams{
			Params:   b.Params.ParametersLiteral(),
			Rlk:      b.GenRelinKey(),
			Rtks:     b.GenRtksKeys(),
			ParamsId: k,
		}
	}
	return pp
}

/*
Given a key, generates a query as a list of list ciphertexts to retrieve the element associated to the key
It assumes that both the querier and the server agree on the same context (i.e crypto params for BFV and key space)
key: key of the element (e.g a subset of the data items, like some keywords)
Returns a list of list of Ciphertexts. Each list is needed to query one of the dimentions of the DB seen as an hypercube.
Inside on of the sublists, you have a list of ciphers when only one is enc(1) to select the index of this dimention, until the last dimention when a plaintext value will be selected
*/
func (PC *PIRClient) QueryGen(key []byte, ctx *settings.PirContext, dimentions, leakage int, weaklyPrivate, compressed bool) (*PIRQuery, float64, error) {
	//new seeded prng
	seed := rand.Int63n(1<<63 - 1)
	prng, err := NewPRNG(seed)
	if err != nil {
		panic(err)
	}
	box := PC.SetsOfBox[ctx.ParamsId]
	box.WithEncoder(bfv.NewEncoder(box.Params))
	box.WithEncryptor(bfv.NewPRNGEncryptor(box.Params, box.Sk).WithPRNG(prng))
	q := new(PIRQuery)
	q.ClientId = PC.Id
	q.ParamsId = ctx.ParamsId
	q.Seed = seed
	q.Dimentions = dimentions
	q.K, q.Kd = settings.RoundUpToDim(float64(ctx.PackedDBSize-1), dimentions)

	leakedBits := 0.0
	if !weaklyPrivate {
		if compressed {
			q.Q, err = PC.compressedQueryGen(key, q.Kd, q.Dimentions, box)
		} else {
			q.Q, err = PC.queryGen(key, q.Kd, q.Dimentions, box)
		}
	} else {
		if compressed == false {
			return nil, 0, errors.New("WPIR queries are not supported without compression")
		}
		if leakage == NONELEAKAGE {
			return nil, 0, errors.New("NONE leakage is supported only if not weakly private query")
		}
		s := 1.0
		if leakage == STANDARDLEAKAGE {
			s = math.Floor(float64(dimentions) / 2)
		}
		if leakage == HIGHLEAKAGE {
			s = float64(dimentions - 1)
		}
		TotBitsLeak := math.Log2(float64(ctx.DBItems))
		leakedBits = (s / float64(dimentions)) * math.Log2(float64(q.K))
		log.Println(fmt.Sprintf("WPIR: Leaking %f / %f", leakedBits, TotBitsLeak))
		q.Q, err = PC.wpQueryGen(key, q.Kd, q.Dimentions, dimentions-1, box)
	}
	return q, leakedBits, err
}

/*
Given a key, generates a query as a list of list ciphertexts to retrieve the element associated to the key
It assumes that both the querier and the server agree on the same context (i.e crypto params for BFV and key space)
key: key of the element (e.g a subset of the data items, like some keywords)
Returns a list of list of Ciphertexts. Each list is needed to query one of the dimentions of the DB seen as an hypercube.
Inside on of the sublists, you have a list of ciphers when only one is enc(1) to select the index of this dimention, until the last dimention when a plaintext value will be selected
*/
func (PC *PIRClient) queryGen(key []byte, Kd, dimentions int, box *settings.HeBox) ([][]*PIRQueryItem, error) {
	if box.Ecd == nil || box.Enc == nil {
		return nil, errors.New("Client is not initliazed with Encoder or Encryptor")
	}
	_, keys := utils.MapKeyToDim(key, Kd, dimentions)
	query := make([][]*PIRQueryItem, dimentions)
	for i, k := range keys {
		queryOfDim := make([]*PIRQueryItem, Kd)
		for d := 0; d < Kd; d++ {
			c := &rlwe.Ciphertext{}
			if d == k {
				//enc 1
				q := make([]uint64, box.Params.N())
				for j := 0; j < len(q); j++ {
					q[j] = 1
				}
				c = box.Enc.EncryptNew(box.Ecd.EncodeNew(q, box.Params.MaxLevel()))
			} else {
				//enc 0
				c = box.Enc.EncryptZeroNew(box.Params.MaxLevel())
			}
			queryOfDim[d] = CompressCT(c)
		}
		query[i] = queryOfDim
	}
	return query, nil
}

func (PC *PIRClient) compressedQueryGen(key []byte, Kd, dimentions int, box *settings.HeBox) ([]*PIRQueryItem, error) {
	if box.Ecd == nil || box.Enc == nil {
		return nil, errors.New("Client is not initliazed with Encoder or Encryptor")
	}
	//l := int(math.Ceil(float64(PC.Context.K) / float64(box.Params.N())))
	_, keys := utils.MapKeyToDim(key, Kd, dimentions)
	selectors := make([][]uint64, dimentions)

	//gen selection vectors
	for i, k := range keys {
		selectors[i] = make([]uint64, Kd)
		selectors[i][k] = 1
	}

	query := make([]*PIRQueryItem, dimentions)
	enc := box.Enc
	ecd := box.Ecd

	for i := range query {
		ct := enc.EncryptNew(utils.EncodeCoeffs(ecd, box.Params, selectors[i]))
		query[i] = CompressCT(ct)
	}
	return query, nil
}

func (PC *PIRClient) AnswerGet(answer []*rlwe.Ciphertext, box *settings.HeBox) ([]byte, error) {
	res := make([]byte, 0)
	for _, a := range answer {
		decrypted := box.Dec.DecryptNew(a)
		decoded := box.Ecd.DecodeUintNew(decrypted)
		value, err := utils.Unchunkify(decoded, settings.TUsableBits)
		if err != nil {
			return nil, err
		}
		res = append(res, value...)
	}
	return res, nil
}

// |
// | W PIR
// v

func (PC *PIRClient) wpQueryGen(key []byte, Kd, dimentions, dimToSkip int, box *settings.HeBox) ([]*PIRQueryItem, error) {
	if box.Ecd == nil || box.Enc == nil {
		return nil, errors.New("Client is not initliazed with Encoder or Encryptor")
	}
	//l := int(math.Ceil(float64(PC.Context.K) / float64(box.Params.N())))
	_, keys := utils.MapKeyToDim(key, Kd, dimentions)
	selectors := make([][]uint64, dimentions-dimToSkip)

	//gen selection vectors
	for i, k := range keys[dimToSkip:] {
		selectors[i] = make([]uint64, Kd)
		selectors[i][k] = 1
	}

	query := make([]*PIRQueryItem, dimentions)
	enc := box.Enc
	ecd := box.Ecd

	for i := range query {
		if i < dimToSkip {
			query[i] = &PIRQueryItem{isPlain: true, Idx: keys[i]}
		} else {
			ct := enc.EncryptNew(utils.EncodeCoeffs(ecd, box.Params, selectors[i-dimToSkip]))
			query[i] = CompressCT(ct)
		}
	}
	return query, nil
}
