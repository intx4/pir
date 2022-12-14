package settings

import (
	"errors"
	"github.com/davidkleiven/gononlin/nonlin"
	"math"
)

/*
Represents a context for the PIR scheme:

	DBItems : num of items in db
	DBSize : size of one item in db in bits (assumes the same for all)
	Dimentions : num dimentions of the hypercube
	N : Ring Degree for BFV in bits
	T : Plaintext Modulus for BFV in bits
	tUsable : Actual Plaintext Modulus to avoid overflow in bits
	MaxBinSize : num of db values that can be stored in one entry of the hypercube
	K : key space of the hypercube
	Kd : dimention size of the hypercube, i.e dth-root of K
*/
type PirContext struct {
	DBItems         int
	DBSize          int
	Dimentions      int
	N               int
	T               int
	TUsable         int
	MaxBinSize      int
	ExpectedBinSize int
	K               int
	Kd              int
	Expansion       bool
}

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
func NewPirContext(Items int, Size int, Dimentions int, N int, T int, tUsable int, expansion bool) (*PirContext, error) {
	if Dimentions < 0 || Dimentions > 3 {
		return nil, errors.New("Hypercube dimention can be 0 to 3")
	}
	PC := &PirContext{DBItems: Items, DBSize: Size, Dimentions: Dimentions, N: N, T: T, TUsable: tUsable, MaxBinSize: int(math.Floor((float64(tUsable) * math.Pow(2, float64(N))) / float64(Size))), Expansion: expansion}

	//compute key space https://link.springer.com/content/pdf/10.1007/3-540-49543-6_13.pdf
	base := math.E
	exp := float64(Dimentions)
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
		if math.Ceil((dc+1)*math.Log(K)) < float64(PC.MaxBinSize)*1.1 && dc != 0.0 {
			PC.ExpectedBinSize = int(math.Ceil((dc + 1) * math.Log(K)))
			PC.K, PC.Kd = RoundUpToDim(K, Dimentions)
			break
		}
		maxIter--
		exp += .1
	}
	if PC.K == 0 {
		return nil, errors.New("Could not estimate probabilistic bin size")
	}
	return PC, nil
}
