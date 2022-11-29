package settings

import (
	"errors"
	"github.com/tuneinsight/lattigo/v4/bfv"
	"github.com/tuneinsight/lattigo/v4/rlwe"
	"math"
)

/*
poly_modulus_degree             | max coeff_modulus bit-length
1024 2048 4096 8192 16384 32768 | 27 54 109 218 438 881
*/
var QI = map[int][]int{
	2048:  []int{54},
	4096:  []int{54, 54},
	8192:  []int{60, 60, 60},
	16384: []int{60, 60, 60},
	32768: []int{60, 60, 60},
}

// Wraps all the struct necessary for BFV
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

func NewHeBox(PC *PirContext) (*HeBox, error) {
	//to do: add checks at some point to make sure that depth is aligned with levels
	params, err := bfv.NewParametersFromLiteral(bfv.ParametersLiteral{
		LogN: PC.N,
		LogQ: QI[int(math.Pow(2.0, float64(PC.N)))], //this is actually QP from the RNS BFV paper
		T:    uint64(65537),
	})
	if err != nil {
		return nil, err
	}
	box := &HeBox{Params: params, Ecd: nil, Evt: nil}
	return box, nil
}

func (B *HeBox) WithKeys(sk *rlwe.SecretKey, pk *rlwe.PublicKey) {
	B.Sk = sk
	B.Pk = pk
}

func (B *HeBox) GenRelinKey() (*rlwe.RelinearizationKey, error) {
	if B.Sk == nil {
		return nil, errors.New("Sk is not initialized")
	}
	rlk := B.Kgen.GenRelinearizationKey(B.Sk, 3)
	return rlk, nil
}

func (B *HeBox) WithKeyGenerator(kgen rlwe.KeyGenerator) {
	B.Kgen = kgen
}

func (B *HeBox) WithEncoder(ecd bfv.Encoder) {
	B.Ecd = ecd
}

func (B *HeBox) WithEncryptor(enc rlwe.Encryptor) {
	B.Enc = enc
}

func (B *HeBox) WithDecryptor(dec rlwe.Decryptor) {
	B.Dec = dec
}

func (B *HeBox) WithEvaluator(evt bfv.Evaluator) {
	B.Evt = evt
}
