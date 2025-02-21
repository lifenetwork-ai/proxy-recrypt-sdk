package pre

import (
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/tuantran-genetica/human-network-crypto-lib/pkg/pre/utils"
)

func TestPreFullFlow(t *testing.T) {
	// Generate system parameters
	scheme := NewPreScheme()
	// Test setup
	// Generate key pair for Alice and Bob
	keyPairAlice := utils.GenerateRandomKeyPair(scheme.G2, scheme.Z)
	keyPairBob := utils.GenerateRandomKeyPair(scheme.G2, scheme.Z)

	// Alice side
	// Generate re-encryption key for Alice->Bob
	reKey := scheme.GenerateReEncryptionKey(keyPairAlice.SecretKey.First, keyPairBob.PublicKey.Second)
	// Alice encrypt a message
	message := "Life is full of unexpected moments that shape who we become. Each day brings new opportunities to learn, grow, and discover something amazing about ourselves and the world around us. When we embrace these challenges with an open mind and willing heart, we find strength we never knew we had. Remember that every step forward, no matter how small, is progress toward your dreams today."
	cipherText := scheme.SecondLevelEncryption(keyPairAlice.PublicKey.First, keyPairBob.SecretKey.First, message, utils.GenerateRandomScalar())

	// Proxy side
	// Re-encrypt the message for Bob
	firstLevelCipherText := scheme.ReEncryption(cipherText, reKey, *keyPairBob.PublicKey.Second)

	// Bob side
	// Decrypt the message
	decryptedMessage := scheme.DecryptFirstLevel(firstLevelCipherText, keyPairBob.SecretKey)

	require.Equal(t, message, decryptedMessage)
}
