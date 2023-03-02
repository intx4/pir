package settings

import (
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
)

// keys is Items|Size|LogN|Dimentions|
type PirContexts struct {
	M map[string]PirContext `json:"M,omitempty"`
}

// Represents a context for the PIR scheme:
type PirContext struct {
	K          int `json:"K,omitempty"`
	Kd         int `json:"Kd,omitempty"`
	Dim        int `json:"Dim,omitempty"`
	ExpBinSize int `json:"ExpBinSize,omitempty"`
	MaxBinSize int `json:"MaxBinSize,omitempty"`
	Items      int `json:"Items"`
	N          int `json:"N,omitempty"`
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
/*
func NewPirContext(Items int, Size int, N int, Dimentions int) (*PirContext, error) {
	ctx := &PirContext{Items: Items, MaxBinSize: int(math.Floor((float64(TUsableBits*N) - math.Log2(float64(TUsableBits*N)) - float64(3*TUsableBits)) / float64(Size+8))), N: N} //- for padding and length, +8 is 1 byte for separator "|"
	//compute key space https://link.springer.com/content/pdf/10.1007/3-540-49543-6_13.pdf
	base := math.E
	alpha := 2.0
	tollerance := 1.0
	for tollerance < 2.0 {
		maxIter := 2000
		exp := 1.1
		for maxIter > 0 {
			K := math.Pow(base, exp)
			c := float64(Items) / (K * math.Log(K))
			//speculatively skip until c is reasonably small
			if math.Ceil((c+1)*exp) >= tollerance*float64(ctx.MaxBinSize) {
				maxIter--
				exp += .01
				continue
			}
			prob := nonlin.Problem{F: func(out, x []float64) {
				out[0] = 1.0 + x[0]*(math.Log(c)-math.Log(x[0])+1.0) - c
			}}
			solver := utils.NewtonKrylov{
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
			if math.Ceil((dc-1+alpha)*exp) < tollerance*float64(ctx.MaxBinSize) && dc != 0.0 {
				ctx.ExpBinSize = int(math.Ceil((dc + 1) * exp))
				ctx.K, ctx.Kd = RoundUpToDim(K, Dimentions)
				if ctx.Kd > N {
					//Kd > N not supported
					ctx.K = 0
					ctx.Kd = 0
					maxIter--
					exp += .01
					continue
				}
				ctx.Dim = Dimentions
				break
			}
			maxIter--
			exp += .01
		}
		if ctx.K != 0 {
			break
		}
		tollerance += 0.1
	}
	if ctx.K == 0 {
		return nil, errors.New("Could not estimate probabilistic bin size or right dimention split, try to adjust the BFV parameters")
	}
	return ctx, nil
}*/

// Takes as input number of items in DB, bit size of items, and params

func NewPirContext(Items int, Size int, N int, Dimentions int) (*PirContext, error) {
	ctx := &PirContext{Items: Items, MaxBinSize: int(math.Floor((float64(TUsableBits*N) - math.Log2(float64(TUsableBits*N)) - float64(3*TUsableBits)) / float64(Size+8))), N: N} //- for padding and length, +8 is 1 byte for separator "|"
	//compute key space https://link.springer.com/content/pdf/10.1007/3-540-49543-6_13.pdf
	alpha := math.Pow(math.E, 1.0/float64(Dimentions))
	tollerance := 1.0
	for tollerance < 8.0 {
		maxIter := 1e5
		exp := 1.1
		for maxIter > 0 {
			n := math.Floor(math.Pow(float64(Items), 1/exp)) //items >> bins*(log bins)^3
			ka := float64(Items)/n + math.Sqrt((2.0*float64(Items)*math.Log(n)/n)*(1-((math.Log(math.Log(n)))/(alpha*2*math.Log(n)))))
			if (float64(ctx.MaxBinSize)*tollerance-ka) <= 15.0*float64(ctx.MaxBinSize)/100 && ((float64(ctx.MaxBinSize) * tollerance) >= ka) { //must be close to Maxbinsize*tollerance. Also not less than 15% of MaxBinSize unused
				ctx.ExpBinSize = int(math.Ceil(ka))
				ctx.K, ctx.Kd = RoundUpToDim(n, Dimentions)
				if ctx.Kd > N {
					//Kd > N not supported
					ctx.K = 0
					ctx.Kd = 0
					maxIter--
					exp += .001
					continue
				}
				ctx.Dim = Dimentions
				break
			}
			maxIter--
			exp += .001
		}
		if ctx.K != 0 {
			break
		}
		tollerance += 1
	}
	if ctx.K == 0 {
		return nil, errors.New("Could not estimate probabilistic bin size or right dimention split, try to adjust the BFV parameters")
	}
	return ctx, nil
}

func (PC *PirContext) Hash() string {
	buf, _ := json.Marshal(PC)
	sum := md5.Sum(buf)
	sumSlice := make([]byte, len(sum))
	for i := range sum {
		sumSlice[i] = sum[i]
	}
	return hex.EncodeToString(sumSlice)
}
