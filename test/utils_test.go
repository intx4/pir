package test

import (
	"bytes"
	"github.com/tuneinsight/lattigo/v4/bfv"
	"pir/settings"
	"pir/utils"
	"testing"
)

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
	lens := []int{50, 76, 100, 250, 395, 471}
	ts := []int{16}

	params, err := bfv.NewParametersFromLiteral(bfv.ParametersLiteral{
		LogN: 12,
		LogQ: settings.QI[2][8192], //this is actually QP from the RNS BFV paper
		T:    uint64(65537),        //Fermat prime
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
