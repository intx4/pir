package test

import (
	"bytes"
	"fmt"
	"github.com/tuneinsight/lattigo/v4/bfv"
	"pir/utils"
	"testing"
)

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

func TestPadding(t *testing.T) {
	lens := []int{50, 76, 100, 250, 395, 471}
	ts := []int{16, 17, 21, 24, 28, 30}

	for _, l := range lens {
		for _, tb := range ts {
			b := RandBinString(l)
			bpad, err := utils.Pad(b, tb)
			if err != nil {
				t.Fatalf(err.Error())
			}
			if len(bpad)%tb != 0 {
				t.Fatalf("Length of pad is not multiple of t")
			}
			bunpad, err := utils.UnPad(bpad, tb)
			if err != nil {
				t.Fatalf(err.Error())
			}
			if b != bunpad {
				t.Fatalf("Unpadded string is not equal to original")
			}
		}
	}
}

func TestByteToBits(t *testing.T) {
	lens := []int{50, 76, 100, 250, 395, 471, 1320, 23495, 432498, 1873763}
	for _, l := range lens {
		b := RandByteString(l)
		bin := utils.BytesToBits(b)
		bnew, err := utils.BitsToBytes(bin, uint64(l))
		if err != nil {
			t.Fatalf(err.Error())
		}
		if bytes.Compare(b, bnew) != 0 {
			t.Fatalf("Bits->bytes is different from original bytes")
		}
	}
}

func TestChunks(t *testing.T) {
	lens := []int{50, 76, 100, 250, 395, 471}
	ts := []int{16, 17, 21, 24, 28, 30}

	for _, l := range lens {
		for _, tb := range ts {
			b := RandByteString(l)
			chunks, err := utils.Chunkify(b, tb)
			if err != nil {
				t.Fatalf(err.Error())
			}
			bnew, err := utils.Unchunkify(chunks, tb)
			if err != nil {
				t.Fatalf(err.Error())
			}
			if bytes.Compare(b, bnew) != 0 {
				t.Fatalf("Unchunkified is different from expected result")
			}
		}
	}
}

func TestEncodeChunks(t *testing.T) {
	lens := []int{50, 76, 100, 250, 395, 471, 8000}
	ts := []int{16}

	params, err := bfv.NewParametersFromLiteral(bfv.ParametersLiteral{
		LogN: 13,
		LogQ: QI[2][8192],   //this is actually QP from the RNS BFV paper
		T:    uint64(65537), //Fermat prime
	})
	if err != nil {
		t.Fatalf(err.Error())
	}
	ecd := bfv.NewEncoder(params)

	for _, l := range lens {
		for _, tb := range ts {
			b := RandByteString(l)
			b = append([]byte{0}, b...)
			chunks, err := utils.Chunkify(b, tb)
			if err != nil {
				t.Fatalf(err.Error())
			}
			pt := ecd.EncodeNew(chunks, params.MaxLevel())
			chunksnew := ecd.DecodeUintNew(pt)
			bnew, err := utils.Unchunkify(chunksnew, tb)
			if err != nil {
				t.Fatalf(err.Error())
			}
			if bytes.Compare(b, bnew) != 0 {
				t.Fatalf("Unchunkified is different from expected result")
			}
		}
	}
}

func TestGenKeysAtDepth(t *testing.T) {
	keys := make([]string, 0)
	utils.GenKeysAtDepth("1|1", 2, 4, 4, &keys)
	fmt.Println(keys)
}

func TestDecompose(t *testing.T) {
	k := 25
	kd := 3
	dim := 3
	s, _ := utils.Decompose(k, kd, dim)
	print(s)
}
