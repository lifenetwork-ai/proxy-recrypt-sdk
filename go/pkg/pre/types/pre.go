package types

import (
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254"
)

type (
	ReencryptionKey = bn254.G2Affine
	Scalar          = big.Int
)
