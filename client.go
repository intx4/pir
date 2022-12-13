package pir

import (
	"errors"
	"github.com/tuneinsight/lattigo/v4/bfv"
	"github.com/tuneinsight/lattigo/v4/rlwe"
	"math"
	"pir/settings"
	"pir/utils"
	"sync"
)

type PIRClient struct {
	Box     settings.HeBox
	Context settings.PirContext
}

func NewPirClient(c settings.PirContext, b settings.HeBox) *PIRClient {
	client := new(PIRClient)
	client.Context = c
	client.Box = b
	client.Box.WithKeyGenerator(bfv.NewKeyGenerator(b.Params))
	client.Box.WithKeys(client.Box.Kgen.GenKeyPair())
	client.Box.WithEncoder(bfv.NewEncoder(client.Box.Params))
	client.Box.WithEncryptor(bfv.NewEncryptor(client.Box.Params, client.Box.Pk))
	client.Box.WithDecryptor(bfv.NewDecryptor(client.Box.Params, client.Box.Sk))
	//client.Box.WithEvaluator(bfv.NewEvaluator(b.Params, rlwe.EvaluationKey{client.Box.Kgen.GenRelinearizationKey(client.Box.Sk, 3), nil}))
	return client
}

func (PC *PIRClient) GenRelinKey() (*rlwe.RelinearizationKey, error) {
	return PC.Box.GenRelinKey()
}

/*
Given a key, generates a query as a list of list ciphertexts to retrieve the element associated to the key
It assumes that both the querier and the server agree on the same context (i.e crypto params for BFV and key space)
key: key of the element (e.g a subset of the data items, like some keywords)

Returns a list of list of Ciphertexts. Each list is needed to query one of the dimentions of the DB seen as an hypercube.
Inside on of the sublists, you have a list of ciphers when only one is enc(1) to select the index of this dimention, until the last dimention when a plaintext value will be selected
*/
func (PC *PIRClient) QueryGen(key []byte) ([][]*rlwe.Ciphertext, error) {
	if PC.Box.Ecd == nil || PC.Box.Enc == nil {
		return nil, errors.New("Client is not initliazed with Encoder or Encryptor")
	}
	_, keys := utils.MapKeyToIdx(key, PC.Context.Kd, PC.Context.Dimentions)
	query := make([][]*rlwe.Ciphertext, PC.Context.Dimentions)
	for i, k := range keys {
		queryOfDim := make([]*rlwe.Ciphertext, PC.Context.Kd)
		for d := 0; d < PC.Context.Kd; d++ {
			c := &rlwe.Ciphertext{}
			if d == k {
				//enc 1
				q := make([]uint64, PC.Box.Params.N())
				for j := 0; j < len(q); j++ {
					q[j] = 1
				}
				c = PC.Box.Enc.EncryptNew(PC.Box.Ecd.EncodeNew(q, PC.Box.Params.MaxLevel())) //-i
			} else {
				//enc 0
				c = PC.Box.Enc.EncryptZeroNew(PC.Box.Params.MaxLevel())
			}
			queryOfDim[d] = c
		}
		query[i] = queryOfDim
	}
	return query, nil
}
func (PC *PIRClient) GenRtKeys() *rlwe.RotationKeySet {
	galoisElts := PC.Box.Params.GaloisElementForExpand(int(math.Ceil(math.Log2(float64(PC.Context.Kd)))))
	return PC.Box.Kgen.GenRotationKeys(galoisElts, PC.Box.Sk)
}

// Encodes d = [d0,d1,...,dn-1] as pt = d0 + d1X + ...dn-1X^n-1 and returns pt in NTT form
func EncodeCoeffs(ecd bfv.Encoder, params bfv.Parameters, coeffs []uint64) *rlwe.Plaintext {
	ptRt := bfv.NewPlaintextRingT(params)

	copy(ptRt.Value.Coeffs[0], coeffs)

	pt := bfv.NewPlaintext(params, params.MaxLevel())
	ecd.ScaleUp(ptRt, pt)

	params.RingQ().NTTLvl(pt.Level(), pt.Value, pt.Value)
	pt.IsNTT = true
	return pt
}

func (PC *PIRClient) CompressedQueryGen(key []byte) ([]*rlwe.Ciphertext, error) {
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
	query := make([]*rlwe.Ciphertext, PC.Context.Dimentions)
	var wg sync.WaitGroup
	for i := range query {
		wg.Add(1)
		go func(i int, ecd bfv.Encoder, enc rlwe.Encryptor) {
			defer wg.Done()
			query[i] = enc.EncryptNew(EncodeCoeffs(ecd, PC.Box.Params, selectors[i]))
		}(i, PC.Box.Ecd.ShallowCopy(), PC.Box.Enc.ShallowCopy())
	}
	wg.Wait()
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
