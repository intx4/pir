package settings

import (
	"github.com/tuneinsight/lattigo/v4/rlwe"
)

// Wrapper for pir profile, containing all the evaluation keys needed for responding the query
type PIRProfile struct {
	Rlk           *rlwe.RelinearizationKey `json:"rlk,omitempty"`
	Rtks          *rlwe.RotationKeySet     `json:"rtks,omitempty"`
	ParamsId      string                   `json:"paramsId"`
	ContextHash   string                   `json:"contextHash"`
	Box           *HeBox                   `json:"-"` //omit, used only locally by client, to be recomputed by server
	KnownByServer bool                     `json:"-"` //omit, used only by client to know if it has to send profiles
}

// Wrapper for a set of profiles from the client, each for every leakage option
type PIRProfileSet struct {
	P map[int]*PIRProfile `json:"p"`
}

func NewProfileSet() *PIRProfileSet {
	return &PIRProfileSet{P: make(map[int]*PIRProfile)}
}
