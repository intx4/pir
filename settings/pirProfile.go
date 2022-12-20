package settings

import "github.com/tuneinsight/lattigo/v4/rlwe"

type PIRCryptoParams struct {
	LogN int      `json:"log_n,omitempty"`
	Q    []uint64 `json:"q,omitempty"`
	P    []uint64 `json:"p,omitempty"`
}

// Wrapper for client profile, containing all the evaluation keys needed for responding the query
type PIRProfile struct {
	Rlk    *rlwe.RelinearizationKey `json:"rlk,omitempty"`
	Rtks   *rlwe.RotationKeySet     `json:"rtks,omitempty"`
	Params []PIRCryptoParams        `json:"params,omitempty"`
	Id     int                      `json:"id,omitempty"`
}
