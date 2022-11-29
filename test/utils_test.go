package test

import (
	"bytes"
	"github.com/tuneinsight/lattigo/v4/bfv"
	"math"
	"math/rand"
	"pir/settings"
	"pir/utils"
	"testing"
)

func RandBinString(n int) string {
	b := ""
	for len(b) < n {
		r := rand.Uint64() % 2
		if r == 0 {
			b += "0"
		} else {
			b += "1"
		}
	}
	return b
}

func RandByteString(n int) []byte {
	b := make([]byte, n)
	rand.Read(b)
	return b
}

func RandChunks(n, t int) []uint64 {
	chunks := make([]uint64, n)
	for i := 0; i < n; i++ {
		r := rand.Uint64()
		for r > uint64(math.Pow(2.0, float64(t))) {
			r = rand.Uint64()
		}
		chunks[i] = r
	}
	return chunks
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
		bnew, err := utils.BitsToBytes(bin)
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
	lens := []int{50, 76, 100, 250, 395, 471}
	ts := []int{16}

	params, err := bfv.NewParametersFromLiteral(bfv.ParametersLiteral{
		LogN: 12,
		LogQ: settings.QI[8192], //this is actually QP from the RNS BFV paper
		T:    uint64(65537),     //Fermat prime
	})
	if err != nil {
		t.Fatalf(err.Error())
	}
	ecd := bfv.NewEncoder(params)

	for _, l := range lens {
		for _, tb := range ts {
			b := RandByteString(l)
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
