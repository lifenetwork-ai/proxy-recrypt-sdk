package utils_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/tuantran-genetica/human-network-crypto-lib/pkg/pre/utils"
)

func TestUtilityFunctions(t *testing.T) {
	t.Run("GenerateRandomString", func(t *testing.T) {
		str1 := utils.GenerateRandomString(32)
		str2 := utils.GenerateRandomString(32)
		require.Len(t, str1, 32)
		require.Len(t, str2, 32)
		require.NotEqual(t, str1, str2)
	})

	t.Run("WriteAsBase64IfNotExists with existing file", func(t *testing.T) {
		tmpFile := filepath.Join(t.TempDir(), "test.txt")
		originalData := []byte("original")
		require.NoError(t, os.WriteFile(tmpFile, originalData, 0600))

		newData := []byte("new")
		err := utils.WriteAsBase64IfNotExists(tmpFile, newData)
		require.NoError(t, err)

		content, err := os.ReadFile(tmpFile)
		require.NoError(t, err)
		require.Equal(t, originalData, content)
	})
}
