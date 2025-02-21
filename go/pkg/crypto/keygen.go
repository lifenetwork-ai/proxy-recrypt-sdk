package crypto

import (
	"crypto/sha256"
	"fmt"
	"io"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"golang.org/x/crypto/hkdf"
)

// GenerateRandomSymmetricKeyFromGT creates a new symmetric key of specified size (16, 24, or 32 bytes)
// by first generating a random element in the GT group and then deriving a symmetric key from it.
// The function returns:
//   - The random GT element that can be used to recreate the key
//   - The derived symmetric key of specified size
//   - An error if key generation or derivation fails
//
// Valid key sizes are:
//   - 16 bytes for AES-128
//   - 24 bytes for AES-192
//   - 32 bytes for AES-256
func GenerateRandomSymmetricKeyFromGT(keySize int) (*bn254.GT, []byte, error) {
	// Validate key size
	if keySize != 16 && keySize != 24 && keySize != 32 {
		return nil, nil, fmt.Errorf("invalid key size: must be 16, 24, or 32 bytes")
	}

	// Generate random GT element
	randomGT, err := new(bn254.GT).SetRandom()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate random GT element: %v", err)
	}

	// Derive key from a point in GT
	symmetricKey, err := DeriveKeyFromGT(randomGT, keySize)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to derive key: %v", err)
	}

	return randomGT, symmetricKey, nil
}

// DeriveKeyFromGT derives a symmetric key of specified size (16, 24, or 32 bytes) from a bn254.GT element.
// The function returns the derived symmetric key or an error if derivation fails.
func DeriveKeyFromGT(gtElement *bn254.GT, keySize int) ([]byte, error) {
	// Validate inputs
	if gtElement == nil {
		return nil, fmt.Errorf("GT element is nil")
	}
	if keySize != 16 && keySize != 24 && keySize != 32 {
		return nil, fmt.Errorf("invalid key size: must be 16, 24, or 32 bytes")
	}

	// Get bytes from GT element
	gtBytes := gtElement.Bytes()
	if len(gtBytes) == 0 {
		return nil, fmt.Errorf("failed to get bytes from GT element")
	}

	// Use HKDF to derive the key
	hkdf := hkdf.New(sha256.New,
		gtBytes[:],                  // Input keying material
		nil,                         // Salt (optional)
		[]byte("PRE_symmetric_key"), // Info (context)
	)

	// Extract the key
	symmetricKey := make([]byte, keySize)
	if _, err := io.ReadFull(hkdf, symmetricKey); err != nil {
		return nil, fmt.Errorf("failed to derive key: %v", err)
	}

	return symmetricKey, nil
}
