package utils

import (
	"math/big"
	mathrand "math/rand"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/tuantran-genetica/human-network-crypto-lib/pkg/pre/types"
)

// generateSystemParameters returns the system parameters for pairing-based cryptography:
// - g1: Generator point of G1 group (in affine coordinates)
// - g2: Generator point of G2 group (in affine coordinates)
// - Z: Pairing result e(g1,g2) which generates the target group GT
//
// These parameters are foundational for constructing pairing-based cryptographic schemes.
// The generators g1 and g2 are obtained from the BN254 curve's built-in generators,
// and Z is computed as their pairing.
func GenerateSystemParameters() (g1 bn254.G1Affine, g2 bn254.G2Affine, Z bn254.GT) {
	_, _, g1, g2 = bn254.Generators()

	Z, _ = bn254.Pair([]bn254.G1Affine{g1}, []bn254.G2Affine{g2})

	return g1, g2, Z
}

func SecretToPubkey(secret *types.SecretKey, g *bn254.G2Affine, Z *bn254.GT) *types.PublicKey {
	return &types.PublicKey{
		First:  new(bn254.GT).Exp(*Z, secret.First),
		Second: g.ScalarMultiplicationBase(secret.Second),
	}
}

// GenerateRandomKeyPair generates a random key pair for the PRE scheme.
// It returns a random key pair with a random public key and secret key.
// The public key is generated from the secret key using the system parameters g and Z.
func GenerateRandomKeyPair(g *bn254.G2Affine, Z *bn254.GT) *types.KeyPair {
	sk := &types.SecretKey{
		First:  GenerateRandomScalar(),
		Second: GenerateRandomScalar(),
	}

	pk := SecretToPubkey(sk, g, Z)

	return &types.KeyPair{
		PublicKey: pk,
		SecretKey: sk,
	}

}

// GenerateRandomScalar generates a random scalar for cryptographic operations.
// It returns a random big.Int scalar value from a random int64.
func GenerateRandomScalar() *big.Int {
	return big.NewInt(mathrand.Int63())
}

func GenerateRandomGTElem() *bn254.GT {
	elem, _ := new(bn254.GT).SetRandom()
	return elem
}

func GenerateRandomG1Elem() *bn254.G1Affine {
	_, _, g1, _ := bn254.Generators()
	randomScalar := GenerateRandomScalar()
	elem := g1.ScalarMultiplicationBase(randomScalar)
	return elem
}
