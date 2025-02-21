package types

import (
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254"
)

// KeyPair represents the key pair components for the PRE scheme
type KeyPair struct {
	PublicKey *PublicKey
	SecretKey *SecretKey
}

// PublicKey represents the public key components for the PRE scheme
type PublicKey struct {
	First  *bn254.GT       // GT is the target group
	Second *bn254.G2Affine // G2Affine represents a point in G2 group
}

// SecretKey represents the secret key components for the PRE scheme
type SecretKey struct {
	First  *big.Int // First component of the secret key, used for the first level encryption
	Second *big.Int // Second component of the secret key, used for the second level encryption
}
