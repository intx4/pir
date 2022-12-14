package test

import (
	"bytes"
	"fmt"
	"github.com/stretchr/testify/require"
	"github.com/tuneinsight/lattigo/v4/bfv"
	"github.com/tuneinsight/lattigo/v4/rgsw"
	"github.com/tuneinsight/lattigo/v4/rlwe"
	"math"
	"pir"
	"pir/settings"
	"pir/utils"
	"testing"
	"time"
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
				context, err := settings.NewPirContext(item, size, dimentions, 14, 65537, 16, false)
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
				context, err := settings.NewPirContext(item, size, dimentions, 14, 65537, 16, false)
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

func EncodeCoeffs(ecd bfv.Encoder, params bfv.Parameters, coeffs []uint64) *rlwe.Plaintext {
	ptRt := bfv.NewPlaintextRingT(params)

	copy(ptRt.Value.Coeffs[0], coeffs)
	//params.RingT().NTTLvl(ptRt.Level(), ptRt.Plaintext.Value, ptRt.Plaintext.Value)
	//ptRt.IsNTT = true
	pt := bfv.NewPlaintext(params, params.MaxLevel())
	ecd.ScaleUp(ptRt, pt)
	//
	//	params.RingQ().NTTLvl(pt.Level(), pt.Value, pt.Value)
	//	pt.IsNTT = true
	return pt
}

func ShowCoeffs(ct *rlwe.Ciphertext, box settings.HeBox) {
	decR := box.Dec.DecryptNew(ct)
	ptRt := bfv.NewPlaintextRingT(box.Params)

	if decR.IsNTT {
		fmt.Println("NTT")
		box.Params.RingQ().InvNTTLvl(decR.Level(), decR.Value, decR.Value)
	}
	box.Ecd.ScaleDown(decR, ptRt)
	fmt.Println(ptRt.Value.Coeffs[0])
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

func TestObliviousExpansionBFVWithRetrieval(t *testing.T) {
	params, _ := bfv.NewParametersFromLiteral(bfv.ParametersLiteral{
		LogN: 12,
		LogQ: []int{35, 35, 35},
		T:    uint64(65537),
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
	rlk := box.Kgen.GenRelinearizationKey(box.Sk, 3)
	box.Evt = bfv.NewEvaluator(params, rlwe.EvaluationKey{Rlk: rlk})
	box.Enc = bfv.NewEncryptor(params, sk)
	box.Dec = bfv.NewDecryptor(params, sk)
	logN := params.LogN()
	logGap := 0

	values := make([]uint64, 4)
	values[2] = 1

	values2 := make([]uint64, 1)
	values2[0] = 1

	// Rotation Keys
	galEls := params.GaloisElementForExpand(logN)
	rtks := box.Kgen.GenRotationKeys(galEls, sk)

	pt := EncodeCoeffs(box.Ecd, box.Params, values)

	//ctIn := bfv.NewCiphertext(box.Params, 1, params.MaxLevel())
	ctIn := box.Enc.EncryptNew(pt) // enc (X^2)
	for _, p := range ctIn.Value {
		box.Params.RingQ().NTTLvl(ctIn.Level(), p, p)
	}
	ctIn.IsNTT = true

	eval := rlwe.NewEvaluator(box.Params.Parameters, &rlwe.EvaluationKey{Rtks: rtks})
	start := time.Now()

	ciphertexts := eval.Expand(ctIn, 2, logGap)
	for _, c := range ciphertexts {
		for _, p := range c.Value {
			box.Params.RingQ().InvNTTLvl(c.Level(), p, p)
		}
		c.IsNTT = false
		ShowCoeffs(c, box)
	}
	end := time.Since(start)
	fmt.Println(":::::::::::::::::::::::::::::::::::::::::::::::::")
	pt = EncodeCoeffs(box.Ecd, box.Params, values2)
	ctIn = box.Enc.EncryptNew(pt) // enc (X^0)
	for _, p := range ctIn.Value {
		box.Params.RingQ().NTTLvl(ctIn.Level(), p, p)
	}
	ctIn.IsNTT = true
	ciphertexts2 := eval.Expand(ctIn, 1, logGap)
	for _, c := range ciphertexts2 {
		for _, p := range c.Value {
			box.Params.RingQ().InvNTTLvl(c.Level(), p, p)
		}
		c.IsNTT = false
		ShowCoeffs(c, box)
	}
	//for _, c := range ciphertexts2 {
	//	utils.ShowCoeffs(c, box)
	//}

	fmt.Println("Time exp ", end)
	data := make([][]uint64, len(ciphertexts))
	for i := range data {
		data[i] = make([]uint64, params.N())
		for j := range data[i] {
			data[i][j] = uint64(i)
		}
	}
	pts := make([]*bfv.PlaintextMul, len(data))
	for i := range pts {
		pts[i] = box.Ecd.EncodeMulNew(data[i], params.MaxLevel())
	}

	start = time.Now()
	result := box.Evt.MulNew(ciphertexts[0], pts[0])

	//[1 0 0 0...] x [2 2 ...2] + 0..0
	for i := 1; i < len(pts); i++ {
		box.Evt.Add(result, box.Evt.MulNew(ciphertexts[i], pts[i]), result)
	}
	r := result.CopyNew()
	decR := box.Dec.DecryptNew(r)
	resP := box.Ecd.DecodeUintNew(decR)
	fmt.Println(resP)
	result2 := box.Evt.MulNew(result, ciphertexts2[0])
	r = result2.CopyNew()
	box.Evt.Relinearize(r, r)
	decR = box.Dec.DecryptNew(r)
	resP = box.Ecd.DecodeUintNew(decR)
	fmt.Println(resP)
	result2 = box.Evt.AddNew(result2, box.Evt.MulNew(result, ciphertexts2[1]))
	r = result2.CopyNew()
	box.Evt.Relinearize(r, r)
	decR = box.Dec.DecryptNew(r)
	resP = box.Ecd.DecodeUintNew(decR)
	fmt.Println(resP)

	//DECRYPT
	box.Evt.Relinearize(result2, result2)
	//Reverse NTT
	r = result2.CopyNew()
	end = time.Since(start)
	fmt.Println("Time: ", end)

	decR = box.Dec.DecryptNew(result2)
	//box.Params.RingQ().InvNTTLvl(decR.Level(), decR.Value, decR.Value)
	resP = box.Ecd.DecodeUintNew(decR)
	for i, r := range resP {
		fmt.Println(data[2][i], r)
		require.Equal(t, data[2][i], r)
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

func TestObliiviousExpansionRGSW(t *testing.T) {
	params, _ := rlwe.NewParametersFromLiteral(rlwe.TestPN13QP218)
	kgen := rlwe.NewKeyGenerator(params)
	sk := kgen.GenSecretKey()
	encryptor := rgsw.NewEncryptor(params, sk)
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

	ctIn := encryptor.EncryptNew(pt)

	// Rotation Keys
	galEls := params.GaloisElementForExpand(logN)

	rtks := kgen.GenRotationKeys(galEls, sk)
	eval := rlwe.NewEvaluator(params, &rlwe.EvaluationKey{Rtks: rtks})
	ctw := rgsw.NewCiphertext(sk.LevelQ(), sk.LevelP(), params.DecompRNS(sk.LevelQ(), sk.LevelP()), params.DecompPw2(sk.LevelQ(), sk.LevelP()), *params.RingQP())
	rgsw.NewEncryptor(params, sk).Encrypt(rlwe.NewPlaintextAtLevelFromPoly(sk.LevelQ(), sk.Value.Q), ctw)
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
