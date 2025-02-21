package crypto_test

import (
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/tuantran-genetica/human-network-crypto-lib/pkg/crypto"
)

func TestAESGCM(t *testing.T) {
	key := make([]byte, 32)
	_, err := rand.Read(key)
	require.NoError(t, err)

	message := "hello, world"
	ciphertext, err := crypto.EncryptAESGCM(message, key)
	require.NoError(t, err)

	plaintext, err := crypto.DecryptAESGCM(ciphertext, key)
	require.NoError(t, err)

	require.Equal(t, message, plaintext)
}
