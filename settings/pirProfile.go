package settings

import (
	"github.com/tuneinsight/lattigo/v4/rlwe"
)

// Wrapper for client profile, containing all the evaluation keys needed for responding the query
type PIRProfile struct {
	Rlk      *rlwe.RelinearizationKey `json:"rlk,omitempty"`
	Rtks     *rlwe.RotationKeySet     `json:"rtks,omitempty"`
	ClientId string                   `json:"id,omitempty"`
}
