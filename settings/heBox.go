package settings

import (
	"errors"
	"github.com/tuneinsight/lattigo/v4/bfv"
	"github.com/tuneinsight/lattigo/v4/rlwe"
)

var T = uint64(65537)
var TUsableBits = 16

/*
poly_modulus_degree             | max coeff_modulus bit-length
1024 2048 4096 8192 16384 32768 | 27 54 109 218 438 881
*/
var QI = map[int]map[int][]int{
	//last in chain needs to be > log(2t) bits (we will have t of noise, so noise budget must be [log(q)-log(t)] - log(t) > 0
	2: {
		//4096:  []int{35, 60}, -> not supported with expansion, too much noise
		8192:  []int{35, 60},
		16384: []int{35, 60},
	},
	3: {
		8192:  []int{35, 60},
		16384: []int{35, 60},
	},
}

var QIforExp = map[int]map[int][]int{
	//last in chain needs to be > log(2t) bits (we will have t of noise, so noise budget must be [log(q)-log(t)] - log(t) > 0
	2: {
		//4096:  []int{35, 60}, -> not supported with expansion, too much noise
		8192:  []int{35, 45, 45, 45},
		16384: []int{35, 45, 45, 45},
	},
	3: {
		8192:  []int{35, 60, 60},
		16384: []int{35, 60, 60},
	},
}

var QIforWP = map[int]map[int][]int{
	//last in chain needs to be > log(2t) bits (we will have t of noise, so noise budget must be [log(q)-log(t)] - log(t) > 0
	2: {
		2048:  []int{35},
		4096:  []int{35},
		8192:  []int{35},
		16384: []int{35},
	},
	3: {
		2048:  []int{35},
		4096:  []int{35},
		8192:  []int{35},
		16384: []int{35},
	},
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

func NewHeBox(logN, dimentions int, expansion bool, weaklyPrivate bool) (*HeBox, error) {
	//to do: add checks at some point to make sure that depth is aligned with levels
	var qi map[int]map[int][]int
	var pi []int = nil
	if expansion == true {
		if !weaklyPrivate {
			qi = QIforExp
		} else {
			qi = QIforWP
		}
	} else {
		qi = QI
	}
	params, err := bfv.NewParametersFromLiteral(bfv.ParametersLiteral{
		LogN: logN,
		LogQ: qi[dimentions][1<<logN], //this is actually QP from the RNS BFV paper
		LogP: pi,
		T:    T,
	})
	if err != nil {
		return nil, err
	}
	box := &HeBox{Params: params}
	return box, nil
}

func (B *HeBox) WithKeys(sk *rlwe.SecretKey, pk *rlwe.PublicKey) {
	B.Sk = sk
	B.Pk = pk
}

func (B *HeBox) WithKey(sk *rlwe.SecretKey) {
	B.Sk = sk
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
