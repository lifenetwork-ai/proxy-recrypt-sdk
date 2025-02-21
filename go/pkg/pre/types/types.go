package types

import (
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254"
)

// PreScheme defines the interface for proxy re-encryption operations
type PreScheme interface {
	GenerateRandomSymmetricKey() *big.Int
	GenerateReEncryptionKey(secretA *big.Int, publicB *bn254.G2Affine) *bn254.G2Affine
	SecondLevelEncryption(pubkeyA *bn254.GT, secretB *big.Int, message *bn254.GT, scalar *big.Int) *SecondLevelCipherText
}
