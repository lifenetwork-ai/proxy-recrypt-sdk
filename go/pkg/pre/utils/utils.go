package utils

import (
	"crypto/rand"
	"encoding/hex"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/tuantran-genetica/human-network-crypto-lib/pkg/crypto"
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

func GenerateRandomScalar() *big.Int {
	// Get the order of BN254 curve
	order := bn254.ID.ScalarField()
	// Generate random scalar in [0, order-1]
	scalar, _ := rand.Int(rand.Reader, order)
	return scalar
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

func GenerateRandomG2Elem() *bn254.G2Affine {
	_, _, _, g2 := bn254.Generators()
	randomScalar := GenerateRandomScalar()
	elem := g2.ScalarMultiplicationBase(randomScalar)
	return elem
}

func GenerateMockSecondLevelCipherText(length int) *types.SecondLevelCipherText {
	return &types.SecondLevelCipherText{
		EncryptedKey: &types.SecondLevelSymmetricKey{
			First:  GenerateRandomG1Elem(),
			Second: GenerateRandomGTElem(),
		},
		EncryptedMessage: GenerateRandomString(length),
	}
}

// GenerateRandomString creates a cryptographically secure random string of fixed length
func GenerateRandomString(length int) string {
	// Calculate number of bytes needed for requested length
	// Each byte becomes 2 hex characters
	bytes := make([]byte, (length+1)/2)

	// Generate random bytes using crypto/rand
	if _, err := rand.Read(bytes); err != nil {
		return ""
	}

	// Convert to hex string and trim to exact length
	return hex.EncodeToString(bytes)[:length]
}

// SecondLevelEncryption performs the second level encryption for the PRE scheme.
// It encrypts a message m ∈ GT under pkA such that it can be decrypted by A and delegatees.
// It takes the public key of A, a portion of secret key of B, the message m and a random scalar as input.
// The scalar is used to randomize the encryption, should not be reused in other sessions.
// It returns the ciphertext in the form of a pair of points in G1 and GT groups.
func MockSecondLevelEnctyption(G1 *bn254.G1Affine, Z *bn254.GT, secretA *types.SecretKey, message string, scalar *big.Int, keyGT *bn254.GT, key []byte) *types.SecondLevelCipherText {

	// check if scalar is in the correct range
	if scalar.Cmp(bn254.ID.ScalarField()) >= 0 {
		panic("scalar is out of range")
	}

	// encrypt the message
	encryptedMessage, err := crypto.EncryptAESGCM(message, key)

	if err != nil {
		panic("error in encryption")
	}

	first := G1.ScalarMultiplicationBase(scalar)
	secondTemp1 := new(bn254.GT).Exp(*Z, secretA.First)
	secondTemp := new(bn254.GT).Exp(*secondTemp1, scalar)
	second := new(bn254.GT).Mul(keyGT, secondTemp)

	encryptedKey := &types.SecondLevelSymmetricKey{
		First:  first,
		Second: second,
	}
	return &types.SecondLevelCipherText{
		EncryptedKey:     encryptedKey,
		EncryptedMessage: encryptedMessage,
	}
}
