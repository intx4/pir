package settings

import "github.com/tuneinsight/lattigo/v4/rlwe"

// Wrapper for client profile, containing all the evaluation keys needed for responding the query
type PIRProfile struct {
	Rlk  *rlwe.RelinearizationKey
	Rtks *rlwe.RotationKeySet
	Seed int64 //feed to PRNG
}

func NewPirProfile(rlk *rlwe.RelinearizationKey, rtks *rlwe.RotationKeySet) PIRProfile {
	return PIRProfile{
		Rlk:  rlk,
		Rtks: rtks,
	}
}
