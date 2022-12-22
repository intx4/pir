package settings

import (
	"github.com/tuneinsight/lattigo/v4/bfv"
	"github.com/tuneinsight/lattigo/v4/rlwe"
)

type PIRCryptoParams struct {
	Params   bfv.ParametersLiteral    `json:"params"`
	Rlk      *rlwe.RelinearizationKey `json:"rlk,omitempty"`
	Rtks     *rlwe.RotationKeySet     `json:"rtks,omitempty"`
	ParamsId string                   `json:"paramsId"`
}

// Wrapper for client profile, containing all the evaluation keys needed for responding the query
type PIRProfile struct {
	CryptoParams []PIRCryptoParams `json:"params,omitempty"`
	ClientId     string            `json:"id,omitempty"`
}
