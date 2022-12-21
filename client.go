package pir

import (
	"errors"
	"fmt"
	"github.com/tuneinsight/lattigo/v4/bfv"
	"github.com/tuneinsight/lattigo/v4/rlwe"
	utils2 "github.com/tuneinsight/lattigo/v4/utils"
	"log"
	"math"
	"math/rand"
	"pir/settings"
	"pir/utils"
)

const (
	NONE int = iota
	STANDARD
	HIGH
)

type PIRClient struct {
	Box     *settings.HeBox
	DiffObl *DiffOblModule
	id      int
}

func NewPirClient(b *settings.HeBox, id int) *PIRClient {
	client := new(PIRClient)
	client.Box = b
	client.Box.WithKeyGenerator(bfv.NewKeyGenerator(b.Params))
	client.Box.WithKey(client.Box.Kgen.GenSecretKey())
	client.Box.WithEncoder(bfv.NewEncoder(client.Box.Params))

	client.id = id
	client.Box.WithDecryptor(bfv.NewDecryptor(client.Box.Params, client.Box.Sk))
	return client
}

func (PC *PIRClient) genRelinKey() (*rlwe.RelinearizationKey, error) {
	return PC.Box.GenRelinKey()
}

func (PC *PIRClient) genRtKeys() *rlwe.RotationKeySet {
	galoisElts := PC.Box.Params.GaloisElementForExpand(PC.Box.Params.LogN())
	return PC.Box.Kgen.GenRotationKeys(galoisElts, PC.Box.Sk)
}

// Creates a new profile to be sent to server
func (PC *PIRClient) GenProfile() (*settings.PIRProfile, error) {
	rlk, err := PC.genRelinKey()
	if err != nil {
		return nil, err
	}
	rtks := PC.genRtKeys()
	return &settings.PIRProfile{
		Rlk:  rlk,
		Rtks: rtks,
		Params: []settings.PIRCryptoParams{settings.PIRCryptoParams{
			LogN: PC.Box.Params.LogN(),
			Q:    PC.Box.Params.Q(),
			P:    PC.Box.Params.P(),
		}},
		Id: PC.id,
	}, nil
}

/*
Given a key, generates a query as a list of list ciphertexts to retrieve the element associated to the key
It assumes that both the querier and the server agree on the same context (i.e crypto params for BFV and key space)
key: key of the element (e.g a subset of the data items, like some keywords)
Returns a list of list of Ciphertexts. Each list is needed to query one of the dimentions of the DB seen as an hypercube.
Inside on of the sublists, you have a list of ciphers when only one is enc(1) to select the index of this dimention, until the last dimention when a plaintext value will be selected
*/
func (PC *PIRClient) QueryGen(key []byte, ctx *settings.PirContext, dimentions, leakage int, weaklyPrivate, compressed bool) (*PIRQuery, error) {
	//new seeded prng
	seed := rand.Int63n(int64(1<<63 - 1))
	rand.Seed(seed)
	keyPRNG := make([]byte, 64)
	rand.Read(keyPRNG)
	prng, err := utils2.NewKeyedPRNG(keyPRNG)
	if err != nil {
		panic(err)
	}
	PC.Box.WithEncryptor(bfv.NewPRNGEncryptor(PC.Box.Params, PC.Box.Sk).WithPRNG(prng))
	q := new(PIRQuery)
	q.Id = PC.id
	q.Seed = seed
	q.Dimentions = dimentions
	q.K, q.Kd = settings.RoundUpToDim(float64(ctx.PackedDBSize-1), dimentions)
	if !weaklyPrivate {
		if compressed {
			q.Q, err = PC.compressedQueryGen(key, q.Kd, q.Dimentions)
		} else {
			q.Q, err = PC.queryGen(key, q.Kd, q.Dimentions)
		}
	} else {
		if compressed == false {
			return nil, errors.New("WPIR queries are not supported without compression")
		}
		if leakage == NONE {
			return nil, errors.New("NONE leakage is supported only if not weakly private query")
		}
		TotBitsLeak := math.Log2(float64(q.K))
		PartitionBitsLeak := math.Log2(float64(q.Kd))
		dimToSkip := 0
		leaked := 0.0
		if leakage == STANDARD {
			for leaked <= TotBitsLeak/2 {
				if leaked+PartitionBitsLeak <= TotBitsLeak/2 {
					leaked += PartitionBitsLeak
					dimToSkip++
				} else {
					break
				}
			}
		} else if leakage == HIGH {
			for leaked <= TotBitsLeak/3 {
				if leaked+PartitionBitsLeak <= TotBitsLeak/3 {
					leaked += PartitionBitsLeak
					dimToSkip++
				} else {
					break
				}
			}
		}
		log.Println(fmt.Sprintf("WPIR: Leaking %f / %f", leaked, TotBitsLeak))
		q.Q, err = PC.wpQueryGen(key, q.Kd, q.Dimentions, dimToSkip)
	}
	return q, err
}

/*
Given a key, generates a query as a list of list ciphertexts to retrieve the element associated to the key
It assumes that both the querier and the server agree on the same context (i.e crypto params for BFV and key space)
key: key of the element (e.g a subset of the data items, like some keywords)
Returns a list of list of Ciphertexts. Each list is needed to query one of the dimentions of the DB seen as an hypercube.
Inside on of the sublists, you have a list of ciphers when only one is enc(1) to select the index of this dimention, until the last dimention when a plaintext value will be selected
*/
func (PC *PIRClient) queryGen(key []byte, Kd, dimentions int) ([][]*PIRQueryItem, error) {
	if PC.Box.Ecd == nil || PC.Box.Enc == nil {
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
				q := make([]uint64, PC.Box.Params.N())
				for j := 0; j < len(q); j++ {
					q[j] = 1
				}
				c = PC.Box.Enc.EncryptNew(PC.Box.Ecd.EncodeNew(q, PC.Box.Params.MaxLevel()))
			} else {
				//enc 0
				c = PC.Box.Enc.EncryptZeroNew(PC.Box.Params.MaxLevel())
			}
			queryOfDim[d] = CompressCT(c)
		}
		query[i] = queryOfDim
	}
	return query, nil
}

func (PC *PIRClient) compressedQueryGen(key []byte, Kd, dimentions int) ([]*PIRQueryItem, error) {
	if PC.Box.Ecd == nil || PC.Box.Enc == nil {
		return nil, errors.New("Client is not initliazed with Encoder or Encryptor")
	}
	//l := int(math.Ceil(float64(PC.Context.K) / float64(PC.Box.Params.N())))
	_, keys := utils.MapKeyToDim(key, Kd, dimentions)
	selectors := make([][]uint64, dimentions)

	//gen selection vectors
	for i, k := range keys {
		selectors[i] = make([]uint64, Kd)
		selectors[i][k] = 1
	}

	query := make([]*PIRQueryItem, dimentions)
	enc := PC.Box.Enc
	ecd := PC.Box.Ecd

	for i := range query {
		ct := enc.EncryptNew(utils.EncodeCoeffs(ecd, PC.Box.Params, selectors[i]))
		query[i] = CompressCT(ct)
	}
	return query, nil
}

func (PC *PIRClient) AnswerGet(answer []*rlwe.Ciphertext) ([]byte, error) {
	res := make([]byte, 0)
	for _, a := range answer {
		decrypted := PC.Box.Dec.DecryptNew(a)
		decoded := PC.Box.Ecd.DecodeUintNew(decrypted)
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

func (PC *PIRClient) wpQueryGen(key []byte, Kd, dimentions, dimToSkip int) ([]*PIRQueryItem, error) {
	if PC.Box.Ecd == nil || PC.Box.Enc == nil {
		return nil, errors.New("Client is not initliazed with Encoder or Encryptor")
	}
	//l := int(math.Ceil(float64(PC.Context.K) / float64(PC.Box.Params.N())))
	_, keys := utils.MapKeyToDim(key, Kd, dimentions)
	selectors := make([][]uint64, dimentions-dimToSkip)

	//gen selection vectors
	for i, k := range keys[dimToSkip:] {
		selectors[i] = make([]uint64, Kd)
		selectors[i][k] = 1
	}

	query := make([]*PIRQueryItem, dimentions)
	enc := PC.Box.Enc
	ecd := PC.Box.Ecd

	for i := range query {
		if i < dimToSkip {
			query[i] = &PIRQueryItem{isPlain: true, Idx: keys[i]}
		} else {
			ct := enc.EncryptNew(utils.EncodeCoeffs(ecd, PC.Box.Params, selectors[i-dimToSkip]))
			query[i] = CompressCT(ct)
		}
	}
	return query, nil
}
