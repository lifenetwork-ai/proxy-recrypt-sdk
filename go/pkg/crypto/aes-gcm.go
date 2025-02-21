package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
)

func EncryptAESGCM(message string, key []byte) (string, error) {
	if len(key) != 16 && len(key) != 24 && len(key) != 32 {
		return "", fmt.Errorf("invalid key size: %d", len(key))
	}

	byteMsg := []byte(message)
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("could not create new cipher: %v", err)
	}

	// Generate a random nonce
	nonce := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("could not generate nonce: %v", err)
	}

	// Create AEAD cipher
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("could not create GCM: %v", err)
	}

	// Encrypt and authenticate
	ciphertext := aead.Seal(nonce, nonce, byteMsg, nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

func DecryptAESGCM(message string, key []byte) (string, error) {
	ciphertext, err := base64.StdEncoding.DecodeString(message)
	if err != nil {
		return "", fmt.Errorf("could not base64 decode: %v", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("could not create new cipher: %v", err)
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("could not create GCM: %v", err)
	}

	if len(ciphertext) < 12 {
		return "", fmt.Errorf("ciphertext too short")
	}

	nonce := ciphertext[:12]
	ciphertext = ciphertext[12:]

	// Decrypt and verify
	plaintext, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", fmt.Errorf("could not decrypt: %v", err)
	}

	return string(plaintext), nil
}
