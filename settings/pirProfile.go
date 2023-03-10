package settings

import (
	"encoding/json"
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

func (pf *PIRProfile) MarshalBinary() ([]byte, error) {
	s := struct {
		Rlk         []byte `json:"rlk,omitempty"`
		Rtks        []byte `json:"rtks,omitempty"`
		ParamsId    string `json:"paramsId"`
		ContextHash string `json:"contextHash"`
	}{
		Rlk:         nil,
		Rtks:        nil,
		ContextHash: pf.ContextHash,
		ParamsId:    pf.ParamsId,
	}
	if pf.Rlk != nil && pf.Rtks != nil {
		s.Rlk, _ = pf.Rlk.MarshalBinary()
		s.Rtks, _ = pf.Rtks.MarshalBinary()
	}
	b, err := json.Marshal(s)
	if err != nil {
		return nil, err
	}
	return b, nil
}

func (pf *PIRProfile) UnMarshalBinary(b []byte) error {
	s := struct {
		Rlk         []byte `json:"rlk,omitempty"`
		Rtks        []byte `json:"rtks,omitempty"`
		ParamsId    string `json:"paramsId"`
		ContextHash string `json:"contextHash"`
	}{
		Rlk:         nil,
		Rtks:        nil,
		ParamsId:    "",
		ContextHash: "",
	}
	err := json.Unmarshal(b, &s)
	if err != nil {
		return err
	}
	if s.Rlk != nil && s.Rtks != nil {
		err = pf.Rlk.UnmarshalBinary(s.Rlk)
		if err != nil {
			return err
		}
		err = pf.Rtks.UnmarshalBinary(s.Rtks)
		if err != nil {
			return err
		}
	}
	pf.ContextHash, pf.ParamsId = s.ContextHash, s.ParamsId
	return nil
}
