package utils

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
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

func SecretToPubkey(secret *types.SecretKey, g *types.G2Affine, Z *types.GT) *types.PublicKey {
	return &types.PublicKey{
		First:  new(types.GT).Exp(*Z, secret.First),
		Second: g.ScalarMultiplicationBase(secret.Second),
	}
}

func GenerateRandomKeyPair(g *types.G2Affine, Z *types.GT) *types.KeyPair {
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
func GenerateRandomScalar() *types.Int {
	return big.NewInt(mathrand.Int63())
}

// GenerateRandomSymmetricKey generates a random symmetric key
func GenerateRandomSymmetricKey() ([]byte, error) {
	key := make([]byte, 32) // 256-bit key
	_, err := rand.Read(key)
	if err != nil {
		return nil, err
	}
	return key, nil
}

func SymmetricEncrypt(message string, key []byte) (string, error) {
	byteMsg := []byte(message)
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("could not create new cipher: %v", err)
	}

	cipherText := make([]byte, aes.BlockSize+len(byteMsg))
	iv := cipherText[:aes.BlockSize]
	if _, err = io.ReadFull(rand.Reader, iv); err != nil {
		return "", fmt.Errorf("could not encrypt: %v", err)
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(cipherText[aes.BlockSize:], byteMsg)

	return base64.StdEncoding.EncodeToString(cipherText), nil
}

func SymmetricDecrypt(message string, key []byte) (string, error) {
	cipherText, err := base64.StdEncoding.DecodeString(message)
	if err != nil {
		return "", fmt.Errorf("could not base64 decode: %v", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("could not create new cipher: %v", err)
	}

	if len(cipherText) < aes.BlockSize {
		return "", fmt.Errorf("invalid ciphertext block size")
	}

	iv := cipherText[:aes.BlockSize]
	cipherText = cipherText[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(cipherText, cipherText)

	return string(cipherText), nil
}
