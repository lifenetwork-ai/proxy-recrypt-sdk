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

// FirstLevelCipherText represents the first level encrypted message components
type FirstLevelCipherText struct {
	First            *bn254.GT // First component of the ciphertext in GT group
	Second           *bn254.GT // Second component of the ciphertext in GT group
	EncryptedMessage string    // The encrypted message, encrypted with the symmetric key
}

// SecondLevelCipherText represents the second level encrypted message components
type SecondLevelCipherText struct {
	First            *bn254.G1Affine // First component of the ciphertext in G1 group
	Second           *bn254.GT       // Second component of the ciphertext in GT group
	EncryptedMessage string          // The encrypted message, encrypted with the symmetric key
}

// PreScheme defines the interface for proxy re-encryption operations
type PreScheme interface {
	GenerateRandomSymmetricKey() *big.Int
	GenerateReEncryptionKey(secretA *big.Int, publicB *bn254.G2Affine) *bn254.G2Affine
	SecondLevelEncryption(pubkeyA *bn254.GT, secretB *big.Int, message *bn254.GT, scalar *big.Int) *SecondLevelCipherText
}
