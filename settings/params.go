package settings

import (
	"fmt"
	"github.com/tuneinsight/lattigo/v4/bfv"
	"strconv"
)

var T = uint64(65537)
var TUsableBits = 16

/*
poly_modulus_degree             | max coeff_modulus bit-length
1024 2048 4096 8192 16384 32768 | 27 54 109 218 438 881
*/
var DEFAULTPARAMS bfv.ParametersLiteral = bfv.ParametersLiteral{T: T, LogN: 13, LogQ: []int{35, 60, 60}, LogP: []int{32, 31}}

// Key = logN|Dimentions|{1|0}(1 if Expansion else 0)|{1|0}(1 if WPIR else 0)|{0|1|2}(0 if no WPIR, 1 if WPIR with STD leakage, 2 if WPIR with high leakage)
var PARAMS = map[string]bfv.ParametersLiteral{
	"12|2|0|0|0": bfv.ParametersLiteral{T: T, LogN: 12, LogQ: []int{35, 54}, LogP: []int{20}}, //no expansion
	"13|2|0|0|0": bfv.ParametersLiteral{T: T, LogN: 13, LogQ: []int{35, 60}, LogP: []int{60}},
	"14|2|0|0|0": bfv.ParametersLiteral{T: T, LogN: 14, LogQ: []int{35, 60}, LogP: []int{60}},
	"12|3|0|0|0": bfv.ParametersLiteral{T: T, LogN: 12, LogQ: []int{35, 54}, LogP: []int{20}}, //no expansion
	"13|3|0|0|0": bfv.ParametersLiteral{T: T, LogN: 13, LogQ: []int{35, 45, 45}, LogP: []int{60}},
	"14|3|0|0|0": bfv.ParametersLiteral{T: T, LogN: 14, LogQ: []int{35, 45, 45}, LogP: []int{60}},
	"12|2|1|0|0": bfv.ParametersLiteral{T: T, LogN: 12, LogQ: []int{35, 30}, LogP: []int{44}}, //expansion
	"13|2|1|0|0": bfv.ParametersLiteral{T: T, LogN: 13, LogQ: []int{35, 40, 40}, LogP: []int{50, 50}},
	"14|2|1|0|0": bfv.ParametersLiteral{T: T, LogN: 14, LogQ: []int{35, 60}, LogP: []int{50, 50}},
	"12|3|1|0|0": bfv.ParametersLiteral{T: T, LogN: 12, LogQ: []int{35, 35}, LogP: []int{39}}, //expansion
	"13|3|1|0|0": bfv.ParametersLiteral{T: T, LogN: 13, LogQ: []int{35, 45, 45}, LogP: []int{45, 45}},
	"14|3|1|0|0": bfv.ParametersLiteral{T: T, LogN: 14, LogQ: []int{35, 50, 50}, LogP: []int{50, 50}},
	"12|2|1|1|1": bfv.ParametersLiteral{T: T, LogN: 12, LogQ: []int{35, 35}, LogP: []int{39}}, //WPIR - d 2 (always 1 mul)
	"12|2|1|1|2": bfv.ParametersLiteral{T: T, LogN: 12, LogQ: []int{35, 35}, LogP: []int{39}},
	"13|2|1|1|1": bfv.ParametersLiteral{T: T, LogN: 13, LogQ: []int{35, 35}, LogP: []int{49, 49, 49}},
	"13|2|1|1|2": bfv.ParametersLiteral{T: T, LogN: 13, LogQ: []int{35, 35}, LogP: []int{49, 49, 49}},
	"14|2|1|1|1": bfv.ParametersLiteral{T: T, LogN: 14, LogQ: []int{35, 35}, LogP: []int{49, 49, 49}},
	"14|2|1|1|2": bfv.ParametersLiteral{T: T, LogN: 14, LogQ: []int{35, 35}, LogP: []int{49, 49, 49}},
	"12|3|1|1|1": bfv.ParametersLiteral{T: T, LogN: 12, LogQ: []int{35, 35}, LogP: []int{39}}, //WPIR - d 3 (if leak 1 -> 2 mul, if leak 2 -> 1 mul)
	"12|3|1|1|2": bfv.ParametersLiteral{T: T, LogN: 12, LogQ: []int{35, 35}, LogP: []int{39}},
	"13|3|1|1|1": bfv.ParametersLiteral{T: T, LogN: 13, LogQ: []int{35, 60}, LogP: []int{60}},
	"13|3|1|1|2": bfv.ParametersLiteral{T: T, LogN: 13, LogQ: []int{35, 35}, LogP: []int{60}},
	"14|3|1|1|1": bfv.ParametersLiteral{T: T, LogN: 14, LogQ: []int{35, 60}, LogP: []int{60}},
	"14|3|1|1|2": bfv.ParametersLiteral{T: T, LogN: 14, LogQ: []int{35, 35}, LogP: []int{60}},
	"12|4|1|1|1": bfv.ParametersLiteral{T: T, LogN: 12, LogQ: []int{35, 35}, LogP: []int{39}}, // NOT USED d > 4 WPIR - d 4 (if leak 1 -> 2 mul, if leak 2 -> 1 mul)
	"12|4|1|1|2": bfv.ParametersLiteral{T: T, LogN: 12, LogQ: []int{35, 35}, LogP: []int{39}},
	"13|4|1|1|1": bfv.ParametersLiteral{T: T, LogN: 13, LogQ: []int{35, 60}, LogP: []int{60, 60}},
	"13|4|1|1|2": bfv.ParametersLiteral{T: T, LogN: 13, LogQ: []int{35, 35}, LogP: []int{60, 60}},
	"14|4|1|1|1": bfv.ParametersLiteral{T: T, LogN: 14, LogQ: []int{35, 60, 60}, LogP: []int{60, 60, 60}},
	"14|4|1|1|2": bfv.ParametersLiteral{T: T, LogN: 14, LogQ: []int{35, 35}, LogP: []int{60, 60, 60, 60}},
	"12|5|1|1|1": bfv.ParametersLiteral{T: T, LogN: 12, LogQ: []int{35, 35}, LogP: []int{39}}, //WPIR - d 5 (if leak 1 -> 3 mul, if leak 2 -> 1 mul)
	"12|5|1|1|2": bfv.ParametersLiteral{T: T, LogN: 12, LogQ: []int{35, 35}, LogP: []int{39}},
	"13|5|1|1|1": bfv.ParametersLiteral{T: T, LogN: 13, LogQ: []int{35, 45, 45}, LogP: []int{45, 45}},
	"13|5|1|1|2": bfv.ParametersLiteral{T: T, LogN: 13, LogQ: []int{35, 35}, LogP: []int{60, 60}},
	"14|5|1|1|1": bfv.ParametersLiteral{T: T, LogN: 14, LogQ: []int{35, 45, 45}, LogP: []int{60, 60, 60, 60}}, //not working
	"14|5|1|1|2": bfv.ParametersLiteral{T: T, LogN: 14, LogQ: []int{35, 35}, LogP: []int{60, 60, 60, 60}},
}

func GetsParamForPIR(logN, dimentions int, expansion, weaklyPrivate bool, leakage int) (string, bfv.Parameters) {
	E := "0"
	if expansion {
		E = "1"
	}
	W := "0"
	if weaklyPrivate {
		W = "1"
	}
	k := strconv.FormatInt(int64(logN), 10) + "|" + strconv.FormatInt(int64(dimentions), 10) + "|" + E + "|" + W + "|" + strconv.FormatInt(int64(leakage), 10)
	if paramsL, ok := PARAMS[k]; !ok {
		panic(fmt.Sprintf("Could not find params for %s", k))
	} else {
		params, err := bfv.NewParametersFromLiteral(paramsL)
		if err != nil {
			panic(err.Error())
		}
		return k, params
	}
}

func ParamsToString(literal bfv.ParametersLiteral) string {
	return fmt.Sprintf("LogN%dT%dLogQ%dLogP%d", literal.LogN, literal.T, literal.LogQ, literal.LogP)
}
