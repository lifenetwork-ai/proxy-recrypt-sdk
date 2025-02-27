package pre_test

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/stretchr/testify/require"
	"github.com/tuantran-genetica/human-network-crypto-lib/pkg/pre"
	"github.com/tuantran-genetica/human-network-crypto-lib/pkg/pre/mocks"
	"github.com/tuantran-genetica/human-network-crypto-lib/pkg/pre/types"
	"github.com/tuantran-genetica/human-network-crypto-lib/pkg/pre/utils"
)

func TestPreFullFlow(t *testing.T) {
	// Generate system parameters
	scheme := pre.NewPreScheme()
	// Test setup
	// Generate key pair for Alice and Bob
	keyPairAlice := utils.GenerateRandomKeyPair(scheme.G2(), scheme.Z())
	keyPairBob := utils.GenerateRandomKeyPair(scheme.G2(), scheme.Z())

	// Alice side
	// Generate re-encryption key for Alice->Bob
	reKey := scheme.GenerateReEncryptionKey(keyPairAlice.SecretKey, keyPairBob.PublicKey)
	// Alice encrypt a message
	message := "Life is full of unexpected moments that shape who we become. Each day brings new opportunities to learn, grow, and discover something amazing about ourselves and the world around us. When we embrace these challenges with an open mind and willing heart, we find strength we never knew we had. Remember that every step forward, no matter how small, is progress toward your dreams today."
	encryptedKey, encryptedMessage, err := scheme.SecondLevelEncryption(keyPairAlice.SecretKey, message, utils.GenerateRandomScalar())
	require.NoError(t, err)

	// Proxy side
	// Re-encrypt the message for Bob
	firstLevelCipherText := scheme.ReEncryption(encryptedKey, reKey)

	// Bob side
	// Decrypt the message
	decryptedMessage := scheme.DecryptFirstLevel(firstLevelCipherText, encryptedMessage, keyPairBob.SecretKey)

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

	encryptedKey, encryptedMessage, err := scheme.SecondLevelEncryption(keyPairAlice.SecretKey, string(scheme.(*mocks.MockPreScheme).Message), scheme.(*mocks.MockPreScheme).Scalar)

	require.NoError(t, err)

	SecondLevelEncryptedKeyFirstBytes := encryptedKey.First.RawBytes()
	SecondLevelEncryptedKeySecondBytes := encryptedKey.Second.Bytes()
	EncryptedDataBytes := encryptedMessage

	err = utils.WriteAsBase64IfNotExists("../../testdata/second_encrypted_key_first.txt", SecondLevelEncryptedKeyFirstBytes[:])
	require.NoError(t, err)

	err = utils.WriteAsBase64IfNotExists("../../testdata/second_encrypted_key_second.txt", SecondLevelEncryptedKeySecondBytes[:])
	require.NoError(t, err)

	err = utils.WriteAsBase64IfNotExists("../../testdata/encrypted_data.txt", EncryptedDataBytes)
	require.NoError(t, err)

	// Proxy side
	// Re-encrypt the message for Bob
	firstLevelCipherText := scheme.ReEncryption(encryptedKey, reKey)

	// Bob side
	// Decrypt the message
	decryptedMessage := scheme.DecryptFirstLevel(firstLevelCipherText, encryptedMessage, keyPairBob.SecretKey)
	require.Equal(t, string(scheme.(*mocks.MockPreScheme).Message), decryptedMessage)

	// Alice side
	// Decrypt the message
	decryptedMessageAlice := scheme.DecryptSecondLevel(encryptedKey, encryptedMessage, keyPairAlice.SecretKey)
	require.Equal(t, string(scheme.(*mocks.MockPreScheme).Message), decryptedMessageAlice)
}

func BenchmarkReEncryption(b *testing.B) {
	scheme := pre.NewPreScheme()
	cipherText := utils.GenerateMockSecondLevelCipherText(500)
	reKey := utils.GenerateRandomG2Elem()
	for n := 0; n < b.N; n++ {
		scheme.ReEncryption(cipherText, reKey)
	}
}

func TestGenerateKeyPair(t *testing.T) {
	scheme := pre.NewPreScheme()

	sk := &types.SecretKey{
		First:  utils.GenerateRandomScalar(),
		Second: utils.GenerateRandomScalar(),
	}

	pk := utils.SecretToPubkey(sk, scheme.G2(), scheme.Z())

	// Pk(Z^a1, g2^a2)

	require.Equal(t, pk.First, new(bn254.GT).Exp(*scheme.Z(), sk.First))
	require.Equal(t, pk.Second, new(bn254.G2Affine).ScalarMultiplication(scheme.G2(), sk.Second))
}
