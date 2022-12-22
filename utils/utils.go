package utils

import (
	"crypto/md5"
	"errors"
	"fmt"
	"github.com/tuneinsight/lattigo/v4/bfv"
	"github.com/tuneinsight/lattigo/v4/rlwe"
	"math"
	"math/big"
	"strconv"
)

var PAD_PREFIX string = "10011111001"
var VALUE_SEPARATOR string = "|"

func IsIn(a []string, v string) bool {
	for i := range a {
		if a[i] == v {
			return true
		}
	}
	return false
}

func Min(a, b float64) float64 {
	if a >= b {
		return b
	}
	return a
}

func Max(a, b float64) float64 {
	if a >= b {
		return a
	}
	return b
}

// Converts b to binary representation
func BytesToBits(b []byte) string {
	//bin := ""
	//for _, byt := range b {
	//	for i := 0; i < 8; i++ {
	//		bin += strconv.Itoa(int(byt & byte(math.Pow(2, float64(i)))))
	//	}
	//}
	//return bin
	n := new(big.Int).SetBytes(b)
	return n.Text(2)
}

func BitsToBytes(b string, l uint64) ([]byte, error) {
	n, ok := new(big.Int).SetString(b, 2)
	if !ok {
		return nil, errors.New("Failed converting bit string to integer")
	}
	p := make([]byte, l)
	n.FillBytes(p)
	return p, nil
}

// Add pad to b (binary string) so to make its len multiple of t_bits. Adds trailing 0 to last chunk of t bits, and adds the pad length as a last chunk
func Pad(b string, tBits int) (string, error) {
	pad := int(math.Ceil(float64(len(b))/float64(tBits))*float64(tBits) - float64(len(b)))
	for i := 0; i < pad; i++ {
		b += "0"
	}
	padBlock, err := strconv.ParseUint(PAD_PREFIX, 2, len(PAD_PREFIX))
	if err != nil {
		return "", err
	}
	for i := 0; i < tBits-len(PAD_PREFIX); i++ {
		padBlock = padBlock << 1
	}
	padBlock |= uint64(pad)
	b += strconv.FormatUint(padBlock, 2)
	return b, err
}

// Given b padded with Pad(), unpads it
func UnPad(b string, tBits int) (string, error) {
	//extract pad block and checks prefix
	padBlock := b[(len(b)/tBits-1)*tBits:]
	prefix := padBlock[:len(PAD_PREFIX)]
	if prefix != PAD_PREFIX {
		return "", errors.New("Bad Padding Error")
	}
	//extract len of padding
	padBlock = padBlock[len(PAD_PREFIX):]
	pad, err := strconv.ParseUint(padBlock, 2, len(padBlock))
	if err != nil {
		return "", err
	}
	b = b[:((len(b)/tBits-1)*tBits - int(pad))]
	return b, err
}

// Divides b into an array of integer each of chunksize bits
func Chunkify(b []byte, chunkSize int) ([]uint64, error) {
	bin, err := Pad(BytesToBits(b), chunkSize)
	if err != nil {
		return nil, err
	}
	//add length of original byte string after padding
	l := strconv.FormatUint(uint64(len(b)), 2)
	for len(l)%chunkSize != 0 {
		l = "0" + l
	}
	bin += l
	binChunks := make([]uint64, len(bin)/chunkSize)
	ii := 0
	for i := 0; i < len(bin); i = i + chunkSize {
		chunk := bin[i : i+chunkSize]
		n, err := strconv.ParseUint(chunk, 2, chunkSize)
		if err != nil {
			return nil, err
		}
		binChunks[ii] = n
		ii++
	}
	return binChunks, err
}

// Encodes chunks as a list of Plaintexts in NTT form
func EncodeChunks(chunks []uint64, ecd bfv.Encoder, params bfv.Parameters) []rlwe.Operand {
	numPts := int(math.Ceil(float64(len(chunks)) / float64(params.N())))
	pts := make([]rlwe.Operand, numPts)
	pti := 0
	for i := 0; i < len(chunks); i = i + params.N() {
		if i+params.N() >= len(chunks) {
			pts[pti] = ecd.EncodeMulNew(chunks[i:], params.MaxLevel())
		} else {
			pts[pti] = ecd.EncodeMulNew(chunks[i:i+params.N()], params.MaxLevel())
		}
		pti++
	}
	return pts
}

// Given an array produced by Chunkify(), returns the underlying byte string
func Unchunkify(chunks []uint64, tBits int) ([]byte, error) {
	bins := make([]string, len(chunks))
	allZero := true
	for i, n := range chunks {
		if n != 0 {
			allZero = false
			b := strconv.FormatUint(n, 2)
			bins[i] = b
		} else {
			bins[i] = "0"
		}
	}
	if allZero {
		return nil, nil
	}
	//trim trailing 0s
	lastZero := len(bins) - 1
	for i := len(bins) - 1; i > 0; i-- {
		if bins[i] == "0" {
			lastZero = i
		} else {
			break
		}
	}

	if bins[lastZero] == "0" {
		bins = bins[:lastZero]
	}

	for i := 0; i < len(bins); i++ {
		//make the string at pos i-th of exactly t bits
		for len(bins[i]) < tBits {
			bins[i] = "0" + bins[i]
		}
	}

	b := ""
	//extract length of data
	l := uint64(0)
	padIdx := 0
	for i := len(bins) - 1; i >= 0; i-- {
		//scan backwords, find pad prefix. Everything after is len
		bin := bins[i]
		if bin[:len(PAD_PREFIX)] == PAD_PREFIX {
			padIdx = i
			break
		}
	}
	lBin := ""
	for i := padIdx + 1; i < len(bins); i++ {
		lBin += bins[i]
	}
	for lBin[0] == '0' {
		//rm trailing 0s
		lBin = lBin[1:]
	}
	l, err := strconv.ParseUint(lBin, 2, len(lBin))
	if err != nil {
		return nil, err
	}
	bins = bins[:padIdx+1]
	for i := range bins {
		b += bins[i]
	}
	b, err = UnPad(b, tBits)
	if err != nil {
		return nil, err
	}
	return BitsToBytes(b, l)
}

// Maps a key to a list of dimentions integers, each in [0,dimSize), as string idx1|...|idxdimentions
func MapKeyToDim(key []byte, dimSize int, dimentions int) (string, []int) {
	h1 := md5.New()

	coords := ""
	coordsV := make([]int, dimentions)
	for i := 0; i < dimentions; i++ {
		h1.Write(key)
		h1.Write([]byte{byte(i)})
		d1 := h1.Sum(nil)
		x := new(big.Int).SetBytes(d1)
		x.Mod(x, new(big.Int).SetInt64(int64(dimSize)))
		coords += x.Text(10) + VALUE_SEPARATOR
		coordsV[i] = int(x.Int64())
		h1.Reset()
	}
	return coords[:len(coords)-1], coordsV
}

// Maps idx in 0...K, K = dimdize^dimentions, to a decomposition of idx in base dimsize
func MapIdxToDim(idx int, dimSize int, dimentions int) (string, []int) {
	coordsV := make([]int, dimentions)
	coords := ""
	j := 0
	for i := dimentions - 1; i >= 0; i-- {
		coordsV[j] = idx / int(math.Pow(float64(dimSize), float64(i)))
		coords += strconv.FormatInt(int64(coordsV[j]), 10) + VALUE_SEPARATOR
		j++
		idx = idx % int(math.Pow(float64(dimSize), float64(i)))
	}
	return coords[:len(coords)-1], coordsV
}

// Recursive function to generate keys at depth nextdepth = currdepth+1 (depth is a dimention)
// totDepth then represents the number of dimentions
// dim is the value of a single dimention
func GenKeysAtDepth(di string, nextDepth, totDepth, dim int, keys *[]string) {
	if nextDepth == totDepth {
		*keys = append(*keys, di)
	} else {
		for dj := 0; dj < dim; dj++ {
			GenKeysAtDepth(di+"|"+strconv.FormatInt(int64(dj), 10), nextDepth+1, totDepth, dim, keys)
		}
	}
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

func ShowCoeffs(ct *rlwe.Ciphertext, decryptor rlwe.Decryptor, ecd bfv.Encoder, params bfv.Parameters) {
	decR := decryptor.DecryptNew(ct)
	ptRt := bfv.NewPlaintextRingT(params)
	if decR.IsNTT {
		fmt.Println("NTT")
		params.RingQ().InvNTTLvl(decR.Level(), decR.Value, decR.Value)
	}
	ecd.ScaleDown(decR, ptRt)
	fmt.Println(ptRt.Value.Coeffs[0][:2])
}

func FormatParams(params bfv.Parameters) string {
	return strconv.FormatInt(int64(params.LogN()), 10) + "|" + strconv.FormatInt(int64(params.LogP()+params.LogQ()), 10)
}
