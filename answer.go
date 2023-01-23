package pir

import "github.com/tuneinsight/lattigo/v4/rlwe"

type PIRAnswer struct {
	Answer []*rlwe.Ciphertext `json:"answer,omitempty"`
}
