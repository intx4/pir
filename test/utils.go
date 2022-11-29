package test

import (
	"math"
	"math/rand"
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
