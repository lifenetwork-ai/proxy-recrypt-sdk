package pre

import (
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/tuantran-genetica/human-network-crypto-lib/pkg/pre/mocks"
	"github.com/tuantran-genetica/human-network-crypto-lib/pkg/pre/utils"
)

func TestPreFullFlow(t *testing.T) {
	// Generate system parameters
	scheme := NewPreScheme()
	// Test setup
	// Generate key pair for Alice and Bob
	keyPairAlice := utils.GenerateRandomKeyPair(scheme.G2(), scheme.Z())
	keyPairBob := utils.GenerateRandomKeyPair(scheme.G2(), scheme.Z())

	// Alice side
	// Generate re-encryption key for Alice->Bob
	reKey := scheme.GenerateReEncryptionKey(keyPairAlice.SecretKey, keyPairBob.PublicKey)
	// Alice encrypt a message
	message := "Life is full of unexpected moments that shape who we become. Each day brings new opportunities to learn, grow, and discover something amazing about ourselves and the world around us. When we embrace these challenges with an open mind and willing heart, we find strength we never knew we had. Remember that every step forward, no matter how small, is progress toward your dreams today."
	cipherText := scheme.SecondLevelEncryption(keyPairAlice.SecretKey, message, utils.GenerateRandomScalar())

	// Proxy side
	// Re-encrypt the message for Bob
	firstLevelCipherText := scheme.ReEncryption(cipherText, reKey)

	// Bob side
	// Decrypt the message
	decryptedMessage := scheme.DecryptFirstLevel(firstLevelCipherText, keyPairBob.SecretKey)

	require.Equal(t, message, decryptedMessage)
}

func TestMockPreFullFlow(t *testing.T) {

	scheme := mocks.NewMockPreScheme()
	// Test setup
	// Generate key pair for Alice and Bob
	keyPairAlice := utils.GenerateRandomKeyPair(scheme.G2(), scheme.Z())
	keyPairBob := utils.GenerateRandomKeyPair(scheme.G2(), scheme.Z())

	// Alice side
	// Generate re-encryption key for Alice->Bob
	reKey := scheme.GenerateReEncryptionKey(keyPairAlice.SecretKey, keyPairBob.PublicKey)
	reKeyBytes := reKey.RawBytes()

	require.Equal(t, reKeyBytes, scheme.(*mocks.MockPreScheme).ReKey.RawBytes())

	cipherText := scheme.SecondLevelEncryption(keyPairAlice.SecretKey, string(scheme.(*mocks.MockPreScheme).Message), scheme.(*mocks.MockPreScheme).Scalar)

	// Store the second level encrypted key and encrypted data for mocks
	// fmt.Println("first point", cipherText.EncryptedKey.First)
	// SecondLevelEncryptedKeyFirstBytes := cipherText.EncryptedKey.First.RawBytes()
	// SecondLevelEncryptedKeySecondBytes := cipherText.EncryptedKey.Second.Bytes()
	// EncryptedDataBytes := []byte(cipherText.EncryptedMessage)

	// utils.WriteAsBase64IfNotExists("./mocks/second_encrypted_key_first.txt", SecondLevelEncryptedKeyFirstBytes[:])
	// utils.WriteAsBase64IfNotExists("./mocks/second_encrypted_key_second.txt", SecondLevelEncryptedKeySecondBytes[:])
	// utils.WriteAsBase64IfNotExists("./mocks/encrypted_data.txt", EncryptedDataBytes)

	// Proxy side
	// Re-encrypt the message for Bob
	firstLevelCipherText := scheme.ReEncryption(cipherText, reKey)

	// Bob side
	// Decrypt the message
	decryptedMessage := scheme.DecryptFirstLevel(firstLevelCipherText, keyPairBob.SecretKey)

	require.Equal(t, string(scheme.(*mocks.MockPreScheme).Message), decryptedMessage)
}

func BenchmarkReEncryption(b *testing.B) {
	scheme := NewPreScheme()
	cipherText := utils.GenerateMockSecondLevelCipherText(500)
	reKey := utils.GenerateRandomG2Elem()
	for n := 0; n < b.N; n++ {
		scheme.ReEncryption(cipherText, reKey)
	}
}
