package settings

import (
	"github.com/tuneinsight/lattigo/v4/bfv"
	"github.com/tuneinsight/lattigo/v4/rlwe"
)

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
	Rtks   *rlwe.RotationKeySet
	Rlk    *rlwe.RelinearizationKey
}

func NewHeBox(params bfv.Parameters) (*HeBox, error) {
	box := &HeBox{Params: params, Kgen: bfv.NewKeyGenerator(params), Ecd: bfv.NewEncoder(params)}
	return box, nil
}

func (B *HeBox) WithKeys(sk *rlwe.SecretKey, pk *rlwe.PublicKey) {
	B.Sk = sk
	B.Pk = pk
}

func (B *HeBox) WithKey(sk *rlwe.SecretKey) {
	B.Sk = sk
}

func (B *HeBox) GenSk() *rlwe.SecretKey {
	sk := B.Kgen.GenSecretKey()
	B.WithKey(sk)
	B.WithDecryptor(rlwe.NewDecryptor(B.Params.Parameters, sk))
	return B.Sk
}

func (B *HeBox) GenRelinKey() *rlwe.RelinearizationKey {
	if B.Sk == nil {
		panic("Sk is not initialized")
	}
	B.Rlk = B.Kgen.GenRelinearizationKey(B.Sk, 3)
	return B.Rlk
}

func (B *HeBox) GenRtksKeys() *rlwe.RotationKeySet {
	galoisElts := B.Params.GaloisElementForExpand(B.Params.LogN())
	B.Rtks = B.Kgen.GenRotationKeys(galoisElts, B.Sk)
	return B.Rtks
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
