package settings

import (
	"errors"
	"github.com/davidkleiven/gononlin/nonlin"
	"github.com/tuneinsight/lattigo/v4/bfv"
	"math"
)

// Represents a context for the PIR scheme:
type PirContext struct {
	DBItems         int `json:"db_items,omitempty"`
	DBSize          int `json:"db_size,omitempty"`
	MaxBinSize      int `json:"max_bin_size,omitempty"`
	ExpectedBinSize int `json:"expected_bin_size,omitempty"`
	PackedDBSize    int `json:"packed_db_size"`
	LogN            int `json:"log_n,omitempty"`
}

// used for estimating bin size from https://link.springer.com/content/pdf/10.1007/3-540-49543-6_13.pdf
var genF = func(c float64) func(x float64) float64 {
	return func(x float64) float64 {
		return 1.0 + x*(math.Log(c)-math.Log(x)+1.0) - c
	}
}

// Takes K and returns NewK and Kd such that pow(Kd,Dim) = NewK >= K
func RoundUpToDim(K float64, Dim int) (int, int) {
	Kd := math.Floor(math.Pow(K, 1.0/float64(Dim)))
	if math.Abs(math.Pow(Kd, float64(Dim))-K) <= 1e-7 {
		return int(math.Floor(K)), int(Kd)
	} else {
		return int(math.Floor(math.Pow(Kd+1, float64(Dim)))), int(Kd + 1)
	}
}

// Takes as input number of items in DB, bit size of items, and params
func NewPirContext(Items int, Size int, params bfv.Parameters) (*PirContext, error) {
	ctx := &PirContext{DBItems: Items, DBSize: Size, MaxBinSize: int(math.Floor(float64(TUsableBits*(1<<params.LogN())-2) / float64(Size+8)))} //-2 for padding and length, +8 is 1 byte for separator "|"
	//compute key space https://link.springer.com/content/pdf/10.1007/3-540-49543-6_13.pdf
	base := math.E
	exp := 2.0
	maxIter := 1000
	for maxIter > 0 {
		K := math.Pow(base, exp)
		c := float64(Items) / (K * math.Log(K))
		prob := nonlin.Problem{F: func(out, x []float64) {
			out[0] = 1.0 + x[0]*(math.Log(c)-math.Log(x[0])+1.0) - c
		}}
		solver := nonlin.NewtonKrylov{
			// Maximum number of Newton iterations
			Maxiter: 1e9,

			// Stepsize used to approximate jacobian with finite differences
			StepSize: 1e-2,

			// Tolerance for the solution
			Tol: 1e-7,
		}
		dc := 0.0
		roots := solver.Solve(prob, []float64{c, math.Pow(c, 2)}).X
		for _, root := range roots {
			if root > c {
				dc = root
				break
			}
		}
		if math.Ceil((dc+1)*math.Log(K)) < float64(ctx.MaxBinSize) && dc != 0.0 {
			ctx.ExpectedBinSize = int(math.Ceil((dc + 1) * math.Log(K)))
			ctx.PackedDBSize = int(math.Ceil(K))
			break
		}
		maxIter--
		exp += .1
	}
	if ctx.PackedDBSize == 0 {
		return nil, errors.New("Could not estimate probabilistic bin size or right dimention split, try to adjust the BFV parameters")
	}
	return ctx, nil
}
