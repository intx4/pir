package pir

import (
	"github.com/tuneinsight/lattigo/v4/bfv"
	"github.com/tuneinsight/lattigo/v4/rlwe"
	"pir/settings"
)

type PIRAnswer struct {
	Answer  []*rlwe.Ciphertext    `json:"answer,omitempty"`
	Context *settings.PirContext  `json:"context, omitempty"`
	Error   string                `json:"status"` //to be read if !ok
	Ok      bool                  `json:"ok"`
	Params  bfv.ParametersLiteral `json:"params"`
}
