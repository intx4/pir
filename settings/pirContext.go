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
}

var genF = func(c float64) func(x float64) float64 {
	return func(x float64) float64 {
		return 1.0 + x*(math.Log(c)-math.Log(x)+1.0) - c
	}
}

func NewPirContext(Items int, Size int, Dimentions int, N int, T int, tUsable int) (*PirContext, error) {
	if Dimentions < 0 || Dimentions > 3 {
		return nil, errors.New("Hypercube dimention can be 0 to 3")
	}
	PC := &PirContext{DBItems: Items, DBSize: Size, Dimentions: Dimentions, N: N, T: T, TUsable: tUsable, MaxBinSize: int(math.Floor((float64(tUsable) * math.Pow(2, float64(N))) / float64(Size)))}

	//compute key space https://link.springer.com/content/pdf/10.1007/3-540-49543-6_13.pdf
	base := 2.0
	maxIter := 1000
	for maxIter > 0 {
		K := math.Pow(base, float64(Dimentions))
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
		if math.Floor((dc+1)*math.Log(K)) < float64(PC.MaxBinSize) && dc != 0.0 {
			PC.ExpectedBinSize = int(math.Floor((dc + 1) * math.Log(K)))
			PC.K = int(K)
			PC.Kd = int(base)
			break
		}
		base++
		maxIter--
	}
	if PC.K == 0 {
		return nil, errors.New("Could not estimate probabilistic bin size")
	}
	return PC, nil
}
