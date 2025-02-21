package crypto_test

import (
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/tuantran-genetica/human-network-crypto-lib/pkg/crypto"
)

func TestGenerateSymmetricKey(t *testing.T) {
	gtElement, symmetricKey, err := crypto.GenerateRandomSymmetricKeyFromGT(32)
	require.NoError(t, err)

	derivedSymmetricKey, err := crypto.DeriveKeyFromGT(gtElement, 32)
	require.NoError(t, err)
	require.Equal(t, symmetricKey, derivedSymmetricKey)
}

func TestGenerateSymmetricKeyInvalidSize(t *testing.T) {
	_, _, err := crypto.GenerateRandomSymmetricKeyFromGT(20)
	require.Error(t, err)
}
