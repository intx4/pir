package pir

import (
	"errors"
	"github.com/tuneinsight/lattigo/v4/bfv"
	"github.com/tuneinsight/lattigo/v4/rlwe"
	utils2 "github.com/tuneinsight/lattigo/v4/utils"
	"log"
	"math/rand"
	"pir/settings"
	"pir/utils"
)

type PIRClient struct {
	Box     *settings.HeBox
	DiffObl *DiffOblModule
	id      string
}

func NewPirClient(b *settings.HeBox, id string) *PIRClient {
	client := new(PIRClient)
	client.Box = b
	client.Box.WithKeyGenerator(bfv.NewKeyGenerator(b.Params))
	client.Box.WithKey(client.Box.Kgen.GenSecretKey())
	client.Box.WithEncoder(bfv.NewEncoder(client.Box.Params))

	client.id = id
	client.Box.WithDecryptor(bfv.NewDecryptor(client.Box.Params, client.Box.Sk))
	return client
}

func (PC *PIRClient) WithDifferentialOblviousness(eps float64, delta float64, n int) error {
	if eps <= 1e-9 {
		return errors.New("Privacy budget too low")
	}
	PC.DiffObl = NewDOModule(DBSizeUpperBound, eps, delta, n)
	log.Print("Sampling noise...")
	PC.DiffObl.GenDPHistogram()
	return nil
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
		LogN: PC.Box.Params.LogN(),
		Q:    PC.Box.Params.Q(),
		P:    PC.Box.Params.P(),
		Id:   PC.id,
	}, nil
}

/*
Given a key, generates a query as a list of list ciphertexts to retrieve the element associated to the key
It assumes that both the querier and the server agree on the same context (i.e crypto params for BFV and key space)
key: key of the element (e.g a subset of the data items, like some keywords)
Returns a list of list of Ciphertexts. Each list is needed to query one of the dimentions of the DB seen as an hypercube.
Inside on of the sublists, you have a list of ciphers when only one is enc(1) to select the index of this dimention, until the last dimention when a plaintext value will be selected
*/
func (PC *PIRClient) QueryGen(key []byte, ctx *settings.PirContext, dimentions int, differentialOblivious, compressed bool) (*PIRQuery, error) {
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

	if !differentialOblivious {
		K, Kd := settings.RoundUpToDim(float64(ctx.PackedSize), dimentions)
		q.K = K
		q.Kd = Kd
		if compressed {
			q.Q, err = PC.compressedQueryGen(key, Kd, dimentions)
		} else {
			q.Q, err = PC.queryGen(key, Kd, dimentions)
		}
	} else {
		if PC.DiffObl == nil {
			return nil, errors.New("Differential Obliviousness module not initialized")
		}
		if compressed == false {
			return nil, errors.New("DO queries are not supported without compression")
		}
		q.Q, q.Ks, err = PC.dpQueryGen(key, ctx.PackedSize, dimentions)
		q.K, q.Kd = settings.RoundUpToDim(float64(len(q.Ks)), dimentions)
		q.Dimentions = dimentions
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
func (PC *PIRClient) queryGen(key []byte, Kd, dimentions int) ([][]*PIRQueryCt, error) {
	if PC.Box.Ecd == nil || PC.Box.Enc == nil {
		return nil, errors.New("Client is not initliazed with Encoder or Encryptor")
	}
	_, keys := utils.MapKeyToDim(key, Kd, dimentions)
	query := make([][]*PIRQueryCt, dimentions)
	for i, k := range keys {
		queryOfDim := make([]*PIRQueryCt, Kd)
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

func (PC *PIRClient) compressedQueryGen(key []byte, Kd, dimentions int) ([]*PIRQueryCt, error) {
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

	query := make([]*PIRQueryCt, dimentions)
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
// | DP PIR
// v

// Given a key, returns an array of noisy keys (including target) and the index of the target key among the noisy keys
func (PC *PIRClient) genNoisyKeys(DBSize, dimentions int, key []byte) ([]string, error) {
	if PC.DiffObl == nil {
		return nil, errors.New("Differential Obliviousness module not initialiazed")
	}
	if PC.DiffObl.DBSize < DBSize {
		PC.DiffObl.DBSize = DBSize
		PC.DiffObl.GenDPHistogram()
	}
	h := PC.DiffObl.H
	_, keyIdx := utils.MapKeyToDim(key, DBSize, 1)
	targetIdx := keyIdx[0]
	N := h[targetIdx]
	_, Kd := settings.RoundUpToDim(float64(N+1), dimentions)
	if Kd > PC.Box.Params.N() {
		return nil, errors.New("The number of noisy keys generated is too high. Try lower epsilon or delta or n")
	}
	noisyIdx := make([]int, N+1)
	i := 0
	for i < N {
		k := rand.Int63n(int64(DBSize))
		if k != int64(targetIdx) {
			noisyIdx[i] = int(k)
			i++
		}
	}
	//add target idx to list of noisy idx
	noisyIdx[len(noisyIdx)-1] = targetIdx
	//transform idx in keys given the dimentions
	noisyKeys := make([]string, len(noisyIdx))
	for i, j := range noisyIdx {
		noisyKeys[i], _ = utils.MapIdxToDim(j, Kd, dimentions)
	}
	//randomly permute the keys
	rand.Shuffle(len(noisyKeys), func(i, j int) {
		noisyKeys[i], noisyKeys[j] = noisyKeys[j], noisyKeys[i]
	})
	return noisyKeys, nil
}

func (PC *PIRClient) dpQueryGen(key []byte, DBSize, dimentions int) ([]*PIRQueryCt, []string, error) {
	Ks, err := PC.genNoisyKeys(DBSize, dimentions, key)
	if err != nil {
		return nil, nil, err
	}
	_, Kd := settings.RoundUpToDim(float64(len(Ks)), dimentions)
	Q, err := PC.compressedQueryGen(key, Kd, dimentions)
	if err != nil {
		return nil, nil, err
	}
	return Q, Ks, nil

}
