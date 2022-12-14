package pir

import (
	"errors"
	"github.com/tuneinsight/lattigo/v4/bfv"
	"github.com/tuneinsight/lattigo/v4/rlwe"
	utils2 "github.com/tuneinsight/lattigo/v4/utils"
	"math"
	"math/rand"
	"pir/settings"
	"pir/utils"
)

type PIRClient struct {
	Box     settings.HeBox
	Context settings.PirContext
	seed    int64
}

func NewPirClient(c settings.PirContext, b settings.HeBox) *PIRClient {
	client := new(PIRClient)
	client.Context = c
	client.Box = b
	client.Box.WithKeyGenerator(bfv.NewKeyGenerator(b.Params))
	client.Box.WithKey(client.Box.Kgen.GenSecretKey())
	client.Box.WithEncoder(bfv.NewEncoder(client.Box.Params))
	client.seed = rand.Int63n(int64(1<<63 - 1))
	rand.Seed(client.seed)
	keyPRNG := make([]byte, 64)
	rand.Read(keyPRNG)
	prng, err := utils2.NewKeyedPRNG(keyPRNG)
	if err != nil {
		panic(err)
	}
	client.Box.WithEncryptor(bfv.NewPRNGEncryptor(client.Box.Params, client.Box.Sk).WithPRNG(prng))
	client.Box.WithDecryptor(bfv.NewDecryptor(client.Box.Params, client.Box.Sk))
	//client.Box.WithEvaluator(bfv.NewEvaluator(b.Params, rlwe.EvaluationKey{client.Box.Kgen.GenRelinearizationKey(client.Box.Sk, 3), nil}))
	return client
}

func (PC *PIRClient) genRelinKey() (*rlwe.RelinearizationKey, error) {
	return PC.Box.GenRelinKey()
}

func (PC *PIRClient) genRtKeys() *rlwe.RotationKeySet {
	galoisElts := PC.Box.Params.GaloisElementForExpand(int(math.Ceil(math.Log2(float64(PC.Context.Kd)))))
	return PC.Box.Kgen.GenRotationKeys(galoisElts, PC.Box.Sk)
}

// Creates a new profile to be sent to server along query
func (PC *PIRClient) GenProfile() (*settings.PIRProfile, error) {
	rlk, err := PC.genRelinKey()
	if err != nil {
		return nil, err
	}
	rtks := PC.genRtKeys()
	return &settings.PIRProfile{
		Rlk:  rlk,
		Rtks: rtks,
		Seed: PC.seed,
	}, nil
}

/*
Given a key, generates a query as a list of list ciphertexts to retrieve the element associated to the key
It assumes that both the querier and the server agree on the same context (i.e crypto params for BFV and key space)
key: key of the element (e.g a subset of the data items, like some keywords)
Returns a list of list of Ciphertexts. Each list is needed to query one of the dimentions of the DB seen as an hypercube.
Inside on of the sublists, you have a list of ciphers when only one is enc(1) to select the index of this dimention, until the last dimention when a plaintext value will be selected
*/
func (PC *PIRClient) QueryGen(key []byte) ([][]*PIRQueryCt, error) {
	if PC.Box.Ecd == nil || PC.Box.Enc == nil {
		return nil, errors.New("Client is not initliazed with Encoder or Encryptor")
	}
	_, keys := utils.MapKeyToIdx(key, PC.Context.Kd, PC.Context.Dimentions)
	query := make([][]*PIRQueryCt, PC.Context.Dimentions)
	for i, k := range keys {
		queryOfDim := make([]*PIRQueryCt, PC.Context.Kd)
		for d := 0; d < PC.Context.Kd; d++ {
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

func (PC *PIRClient) CompressedQueryGen(key []byte) ([]*PIRQueryCt, error) {
	if PC.Box.Ecd == nil || PC.Box.Enc == nil {
		return nil, errors.New("Client is not initliazed with Encoder or Encryptor")
	}
	//l := int(math.Ceil(float64(PC.Context.K) / float64(PC.Box.Params.N())))
	_, keys := utils.MapKeyToIdx(key, PC.Context.Kd, PC.Context.Dimentions)
	selectors := make([][]uint64, PC.Context.Dimentions)

	//gen selection vectors
	for i, k := range keys {
		selectors[i] = make([]uint64, PC.Context.Kd)
		selectors[i][k] = 1
	}

	////concat vectors
	//concatSelectors := make([][]uint64, l)
	//for i := range concatSelectors {
	//	concatSelectors[i] = make([]uint64, PC.Box.Params.N())
	//}
	//offset := 0
	//for i := range concatSelectors {
	//	if offset > PC.Context.K {
	//		break
	//	}
	//	di := int(math.Floor(float64(offset) / float64(PC.Context.Kd)))
	//	dj := offset % PC.Context.Kd
	//	for j := 0; j < PC.Box.Params.N(); j++ {
	//		concatSelectors[i][j] = selectors[di][dj]
	//		offset++
	//	}
	//}
	query := make([]*PIRQueryCt, PC.Context.Dimentions)
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
		value, err := utils.Unchunkify(decoded, PC.Context.TUsable)
		if err != nil {
			return nil, err
		}
		res = append(res, value...)
	}
	return res, nil
}
