package test

import (
	"bytes"
	"fmt"
	"github.com/stretchr/testify/require"
	"github.com/tuneinsight/lattigo/v4/bfv"
	"github.com/tuneinsight/lattigo/v4/rlwe"
	"math"
	"pir"
	"pir/settings"
	"pir/utils"
	"testing"
)

// This test takes time
func TestServerEncode(t *testing.T) {
	//various settings for the db size
	items := []int{1 << 10, 1 << 12}
	sizes := []int{150 * 8, 250 * 8}

	for _, item := range items {
		for _, size := range sizes {
			for _, dimentions := range []int{2, 3} {
				//we first create a context for the protocol, including info about the db size
				//the dimentions we need to represent the db by (e.g 2 for matrix representation)
				//the parameters of the BFV scheme (N,T and usable bits of T)
				context, err := settings.NewPirContext(item, size, dimentions, 14, 65537, 16)
				if err != nil {
					t.Fatalf(err.Error())
				}
				//we then create a HeBox with the context. This wraps all the tools needed for crypto stuff
				box, err := settings.NewHeBox(context)
				if err != nil {
					t.Fatalf(err.Error())
				}
				//let's generate some fake values
				keys := make([][]byte, item)
				values := make([][]byte, item)
				for i := range keys {
					keys[i] = RandByteString(100)
					values[i] = RandByteString(size)
				}
				server, err := pir.NewPirServer(*context, *box, keys, values)
				if err != nil {
					t.Fatalf(err.Error())
				}
				//let's verify that values are encoded as expected
				if ecdStore, err := server.Encode(); err != nil {
					t.Fatalf(err.Error())
				} else {
					ecdStorageAsMap := make(map[string][]*bfv.PlaintextMul)
					ecdStore.Range(func(key, value any) bool {
						valueToStore := make([]*bfv.PlaintextMul, len(value.([]rlwe.Operand)))
						for i, v := range value.([]rlwe.Operand) {
							valueToStore[i] = v.(*bfv.PlaintextMul)
						}
						ecdStorageAsMap[key.(string)] = valueToStore
						return true
					})
					for k, v := range ecdStorageAsMap {
						expected := server.Store[k].Coalesce()
						actual := box.Ecd.DecodeUintNew(v[0])
						for i := 1; i < len(v); i++ {
							actual = append(actual, box.Ecd.DecodeUintNew(v[i])...)
						}
						actualBytes, err := utils.Unchunkify(actual, context.TUsable)
						if err != nil {
							t.Fatalf(err.Error())
						}
						if len(actualBytes) != len(expected) {
							t.Fatalf("Len of decoded value is not same as original")
						}
						for i := range expected {
							if actualBytes[i] != expected[i] {
								t.Fatalf("Decoded value does not match original")
							}
						}
					}
				}
			}
		}
	}
}

func TestServerEntryManipulation(t *testing.T) {
	//various settings for the db size
	items := []int{1 << 10, 1 << 12, 1 << 14, 1 << 16}
	sizes := []int{150 * 8, 250 * 8}

	for _, item := range items {
		for _, size := range sizes {
			for _, dimentions := range []int{2, 3} {
				//we first create a context for the protocol, including info about the db size
				//the dimentions we need to represent the db by (e.g 2 for matrix representation)
				//the parameters of the BFV scheme (N,T and usable bits of T)
				context, err := settings.NewPirContext(item, size, dimentions, 14, 65537, 16)
				if err != nil {
					t.Fatalf(err.Error())
				}
				//we then create a HeBox with the context. This wraps all the tools needed for crypto stuff
				box, err := settings.NewHeBox(context)
				if err != nil {
					t.Fatalf(err.Error())
				}
				//let's generate some fake values
				keys := make([][]byte, item)
				values := make([][]byte, item)
				for i := range keys {
					keys[i] = RandByteString(100)
					values[i] = RandByteString(size)
				}
				server, err := pir.NewPirServer(*context, *box, keys, values)
				k, _ := utils.MapKeyToIdx(keys[0], context.Kd, context.Dimentions)
				oldV := server.Store[k].Value
				if err != nil {
					t.Fatalf(err.Error())
				}
				pos1, err := server.Add(keys[0], values[0])
				if err != nil {
					t.Fatalf(err.Error())
				}
				pos2, err := server.Add(keys[0], values[1])
				if err != nil {
					t.Fatalf(err.Error())
				}
				err = server.Modify(keys[0], values[1], pos1)
				if err != nil {
					t.Fatalf(err.Error())
				}
				err = server.Modify(keys[0], values[2], pos2)
				if err != nil {
					t.Fatalf(err.Error())
				}
				err = server.Delete(keys[0], pos1)
				if err != nil {
					t.Fatalf(err.Error())
				}
				err = server.Delete(keys[0], pos2-1)
				for i := range oldV {
					if bytes.Compare(oldV[i], server.Store[k].Value[i]) != 0 {
						t.Fatalf("Comparison fail")
					}
				}
			}
		}
	}
}

func TestObliiviousExpansionBFV(t *testing.T) {
	params, _ := bfv.NewParametersFromLiteral(bfv.ParametersLiteral{
		LogN:     12,
		LogQ:     []int{35, 35, 35},
		LogP:     nil,
		Pow2Base: 0,
		Sigma:    0,
		H:        0,
		T:        uint64(65537),
	})
	box := settings.HeBox{
		Params: params,
		Sk:     nil,
		Pk:     nil,
		Kgen:   bfv.NewKeyGenerator(params),
		Ecd:    bfv.NewEncoder(params),
		Enc:    nil,
		Dec:    nil,
		Evt:    nil,
	}
	sk, pk := box.Kgen.GenKeyPair()
	box.Sk = sk
	box.Pk = pk
	rlk, _ := box.GenRelinKey()
	box.Evt = bfv.NewEvaluator(params, rlwe.EvaluationKey{Rlk: rlk})
	box.Enc = bfv.NewEncryptor(params, pk)
	box.Dec = bfv.NewDecryptor(params, sk)
	logN := params.LogN()
	logGap := 0
	gap := 1

	ptRt := bfv.NewPlaintextRingT(box.Params)

	values := make([]uint64, params.N())
	scale, _ := utils.InvMod(1<<logN, params.T())
	scale = 1
	values[2] = scale

	copy(ptRt.Value.Coeffs[0], values)

	pt := bfv.NewPlaintext(box.Params, box.Params.MaxLevel())
	box.Ecd.ScaleUp(ptRt, pt)

	//put in NTT for expand
	params.RingQ().NTTLvl(pt.Level(), pt.Value, pt.Value)
	pt.IsNTT = true

	ctIn := bfv.NewCiphertext(box.Params, 1, params.MaxLevel())
	box.Enc.Encrypt(pt, ctIn)

	// Rotation Keys
	galEls := params.GaloisElementForExpand(logN)

	rtks := box.Kgen.GenRotationKeys(galEls, sk)

	eval := rlwe.NewEvaluator(box.Params.Parameters, &rlwe.EvaluationKey{Rtks: rtks})

	ciphertexts := eval.Expand(ctIn, logN, logGap)

	bound := uint64(params.N() * params.N())

	for i := range ciphertexts {
		box.Dec.Decrypt(ciphertexts[i], pt)

		if pt.IsNTT {
			params.RingQ().InvNTTLvl(pt.Level(), pt.Value, pt.Value)
		}

		box.Ecd.ScaleDown(pt, ptRt)

		for j := 0; j < ptRt.Level()+1; j++ {

			T := params.RingT().Modulus[j]
			QHalf := T >> 1

			for k, c := range ptRt.Value.Coeffs[j] {

				if c >= QHalf {
					c = T - c
				}

				if k != 0 {
					require.Greater(t, bound, c)
					require.Equal(t, int64(0), int64(c))
				} else {
					require.InDelta(t, 0, math.Abs(float64(values[i*gap]/scale)-float64(c)), 0.0001)
					fmt.Println(values[i*gap], int64(c))
					fmt.Println()
				}
			}
		}
	}
}

func EncodeCoeffs(ecd bfv.Encoder, params bfv.Parameters, coeffs []uint64) *rlwe.Plaintext {
	ptRt := bfv.NewPlaintextRingT(params)

	copy(ptRt.Value.Coeffs[0], coeffs)

	pt := bfv.NewPlaintext(params, params.MaxLevel())
	ecd.ScaleUp(ptRt, pt)

	params.RingQ().NTTLvl(pt.Level(), pt.Value, pt.Value)
	pt.IsNTT = true
	return pt
}

type HeBox struct {
	Params bfv.Parameters
	Sk     *rlwe.SecretKey
	Pk     *rlwe.PublicKey
	Kgen   rlwe.KeyGenerator
	Ecd    bfv.Encoder
	Enc    rlwe.Encryptor
	Dec    rlwe.Decryptor
	Evt    bfv.Evaluator
}

func TestObliiviousExpansionBFVWithRetrieval(t *testing.T) {
	//params, _ := bfv.NewParametersFromLiteral(bfv.ParametersLiteral{
	//	LogN:     12,
	//	LogQ:     []int{35, 35, 35},
	//	LogP:     nil,
	//	Pow2Base: 0,
	//	Sigma:    0,
	//	H:        0,
	//	T:        uint64(65537),
	//})
	params, _ := bfv.NewParametersFromLiteral(bfv.PN11QP54)
	box := HeBox{
		Params: params,
		Sk:     nil,
		Pk:     nil,
		Kgen:   bfv.NewKeyGenerator(params),
		Ecd:    bfv.NewEncoder(params),
		Enc:    nil,
		Dec:    nil,
		Evt:    nil,
	}
	sk, pk := box.Kgen.GenKeyPair()
	box.Sk = sk
	box.Pk = pk
	rlk := box.Kgen.GenRelinearizationKey(box.Sk, 3)
	box.Evt = bfv.NewEvaluator(params, rlwe.EvaluationKey{Rlk: rlk})
	box.Enc = bfv.NewEncryptor(params, pk)
	box.Dec = bfv.NewDecryptor(params, sk)
	logN := params.LogN()
	logGap := 0

	values := make([]uint64, params.N())
	values[2] = 1

	pt := EncodeCoeffs(box.Ecd, box.Params, values)

	ctIn := bfv.NewCiphertext(box.Params, 1, params.MaxLevel())
	box.Enc.Encrypt(pt, ctIn) // enc (X^2)

	// Rotation Keys
	galEls := params.GaloisElementForExpand(logN)

	rtks := box.Kgen.GenRotationKeys(galEls, sk)

	eval := rlwe.NewEvaluator(box.Params.Parameters, &rlwe.EvaluationKey{Rtks: rtks})

	ciphertexts := eval.Expand(ctIn, logN, logGap)

	data := make([][]uint64, len(ciphertexts))
	for i := range data {
		data[i] = make([]uint64, params.N())
		for j := range data[i] {
			data[i][j] = uint64(i)
		}
	}
	pts := make([]*rlwe.Plaintext, len(data))

	fmt.Println("level", ciphertexts[0].Level()-params.MaxLevel())
	for i := range pts {
		pts[i] = EncodeCoeffs(box.Ecd, box.Params, data[i])
		if !pts[i].IsNTT {
			params.RingQ().NTTLvl(pts[i].Level(), pts[i].Value, pts[i].Value)
			pts[i].IsNTT = true
		} else {
			params.RingQ().InvNTTLvl(pts[i].Level(), pts[i].Value, pts[i].Value)
			pts[i].IsNTT = false
		}
	}
	ptRt := bfv.NewPlaintextRingT(params)

	decR := box.Dec.DecryptNew(ciphertexts[2])
	if decR.IsNTT {
		fmt.Println("NTT")
		params.RingQ().InvNTTLvl(decR.Level(), decR.Value, decR.Value)
	}
	box.Ecd.ScaleDown(decR, ptRt)
	fmt.Println(ptRt.Value.Coeffs[0]) //[1 0 0 0...0]

	pt.Copy(pts[2])
	if pt.IsNTT {
		fmt.Println("NTT")
		params.RingQ().InvNTTLvl(pt.Level(), pt.Value, pt.Value)
	}
	box.Ecd.ScaleDown(pt, ptRt)
	fmt.Println(ptRt.Value.Coeffs[0]) //[2 2 2 2 2 2...2]

	//reverse NTT
	for _, p := range ciphertexts[2].Value {
		box.Params.RingQ().InvNTTLvl(ciphertexts[2].Level(), p, p)
		ciphertexts[2].IsNTT = false
	}
	decR = box.Dec.DecryptNew(ciphertexts[2])
	if decR.IsNTT {
		fmt.Println("NTT")
		params.RingQ().InvNTTLvl(decR.Level(), decR.Value, decR.Value)
	}
	box.Ecd.ScaleDown(decR, ptRt)
	fmt.Println(ptRt.Value.Coeffs[0]) //[1 0 0 0...0]

	result := box.Evt.MulNew(ciphertexts[2], pts[2]) //[1 0 0 0...] x [2 2 ...2]

	decR = box.Dec.DecryptNew(result)
	if decR.IsNTT {
		fmt.Println("NTT")
		params.RingQ().InvNTTLvl(decR.Level(), decR.Value, decR.Value)
	}
	box.Ecd.ScaleDown(decR, ptRt)
	fmt.Println(ptRt.Value.Coeffs[0])

	for i, c := range ptRt.Value.Coeffs[0] {
		T := params.RingT().Modulus[0]
		THalf := T >> 1
		if c >= THalf {
			c = T - c
		}
		require.Equal(t, data[2][i], c)
	}
}

func TestObliiviousExpansionRLWE(t *testing.T) {
	params, _ := rlwe.NewParametersFromLiteral(rlwe.TestPN13QP218)
	kgen := rlwe.NewKeyGenerator(params)
	sk := kgen.GenSecretKey()
	encryptor := rlwe.NewEncryptor(params, sk)
	decryptor := rlwe.NewDecryptor(params, sk)
	pt := rlwe.NewPlaintext(params, params.MaxLevel())

	logN := params.LogN()
	logGap := 0
	gap := 1 << logGap
	scale := 1 << 24

	values := make([]uint64, params.N())
	values[2] = uint64(scale)

	for i := 0; i < pt.Level()+1; i++ {
		copy(pt.Value.Coeffs[i], values)
	}

	params.RingQ().NTTLvl(pt.Level(), pt.Value, pt.Value)
	pt.IsNTT = true

	ctIn := rlwe.NewCiphertext(params, 1, params.MaxLevel())
	encryptor.Encrypt(pt, ctIn)

	// Rotation Keys
	galEls := params.GaloisElementForExpand(logN)

	rtks := kgen.GenRotationKeys(galEls, sk)

	eval := rlwe.NewEvaluator(params, &rlwe.EvaluationKey{Rtks: rtks})

	ciphertexts := eval.Expand(ctIn, logN, logGap)

	bound := uint64(params.N() * params.N())

	for i := range ciphertexts {

		decryptor.Decrypt(ciphertexts[i], pt)

		if pt.IsNTT {
			params.RingQ().InvNTTLvl(pt.Level(), pt.Value, pt.Value)
		}

		for j := 0; j < pt.Level()+1; j++ {

			Q := params.RingQ().Modulus[j]
			QHalf := Q >> 1

			for k, c := range pt.Value.Coeffs[j] {

				if c >= QHalf {
					c = Q - c
				}

				if k != 0 {
					require.Greater(t, bound, c)
					require.Equal(t, int64(0), int64(c)/int64(scale))
				} else {
					require.InDelta(t, 0, math.Abs(float64(values[i*gap])-float64(c))/float64(scale), 0.5)
					fmt.Println(values[i*gap]/uint64(scale), int64(c)/int64(scale))
					fmt.Println()
				}
			}
		}
	}
}
