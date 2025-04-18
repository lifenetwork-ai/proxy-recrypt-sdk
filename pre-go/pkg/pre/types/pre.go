package types

import (
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254"
)

type (
	ReEncryptionKey = bn254.G2Affine
	Scalar          = big.Int
)
