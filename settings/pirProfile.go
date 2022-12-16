package settings

import "github.com/tuneinsight/lattigo/v4/rlwe"

// Wrapper for client profile, containing all the evaluation keys needed for responding the query
type PIRProfile struct {
	Rlk  *rlwe.RelinearizationKey
	Rtks *rlwe.RotationKeySet
	LogN int
	Q    []uint64
	P    []uint64
	Id   int
}
