package pre

import (
	"encoding/base64"
	"os"
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
	// Generate system parameters
	scheme := mocks.NewMockPreScheme()
	// Test setup
	// Generate key pair for Alice and Bob
	keyPairAlice := utils.GenerateRandomKeyPair(scheme.G2(), scheme.Z())
	keyPairBob := utils.GenerateRandomKeyPair(scheme.G2(), scheme.Z())

	// Alice side
	// Generate re-encryption key for Alice->Bob
	reKey := scheme.GenerateReEncryptionKey(keyPairAlice.SecretKey, keyPairBob.PublicKey)
	reKeyBytes := reKey.Bytes()

	// load rekey from file
	reKeyBase64FromFile, err := os.ReadFile("./mocks/rekey.txt")
	require.NoError(t, err)
	reKeyBytes2, err := base64.StdEncoding.DecodeString(string(reKeyBase64FromFile))
	require.NoError(t, err)
	require.Equal(t, reKeyBytes[:], reKeyBytes2)

	// Alice encrypt a message
	message, _ := mocks.LoadMockData()
	cipherText := scheme.SecondLevelEncryption(keyPairAlice.SecretKey, string(message), utils.GenerateRandomScalar())

	// Proxy side
	// Re-encrypt the message for Bob
	firstLevelCipherText := scheme.ReEncryption(cipherText, reKey)

	// Bob side
	// Decrypt the message
	decryptedMessage := scheme.DecryptFirstLevel(firstLevelCipherText, keyPairBob.SecretKey)

	require.Equal(t, string(message), decryptedMessage)
}

func BenchmarkReEncryption(b *testing.B) {
	scheme := NewPreScheme()
	cipherText := utils.GenerateMockSecondLevelCipherText(500)
	reKey := utils.GenerateRandomG2Elem()
	for n := 0; n < b.N; n++ {
		scheme.ReEncryption(cipherText, reKey)
	}
}
