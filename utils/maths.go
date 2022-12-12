package utils

import (
	"errors"
	"fmt"
	"math/big"
)

func InvMod(x uint64, base uint64) (uint64, error) {
	X := big.NewInt(int64(x))
	Base := big.NewInt(int64(base))
	// Compute inverse of X modulo Base
	bigGcd := big.NewInt(0)
	I := big.NewInt(0)
	bigGcd.GCD(I, nil, X, Base)
	if bigGcd.Uint64() != 1 {
		return 0, errors.New(fmt.Sprintf("could not find %d^-1 mod %d... check if it is invertible", x, base))
	}
	return I.Uint64(), nil
}
