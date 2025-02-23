package mocks

import (
	"encoding/base64"
	"os"
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/stretchr/testify/require"
)

func TestSerializeDeserializeKeyPair(t *testing.T) {
	// Create a temporary file for testing
	tmpFile, err := os.CreateTemp(".", "keypair_test_*.json")
	require.NoError(t, err)
	defer os.Remove(tmpFile.Name()) // Clean up after test

	// Save a keypair to the file
	err = SaveKeyPairToFile(tmpFile.Name())
	require.NoError(t, err)

	// Load the keypair from the file
	loadedKeyPair, err := LoadKeyPairFromFile(tmpFile.Name())
	require.NoError(t, err)

	// Verify that the loaded keypair is valid
	require.NotNil(t, loadedKeyPair)
	require.NotNil(t, loadedKeyPair.PublicKey)
	require.NotNil(t, loadedKeyPair.SecretKey)
	require.NotNil(t, loadedKeyPair.PublicKey.First)
	require.NotNil(t, loadedKeyPair.PublicKey.Second)
}

func TestLoadKeyPairFromFile(t *testing.T) {
	// Read alice keypair
	aliceKeyPair, err := LoadKeyPairFromFile("alice_keypair.json")
	require.NoError(t, err)
	require.NotNil(t, aliceKeyPair)
	require.Equal(t, 128, bn254.SizeOfG2AffineUncompressed)
	require.NotNil(t, aliceKeyPair.SecretKey)
	require.Equal(t, "1b3c4f2629e642f076a6f9da84d8dba47176d88659e2027193d1a9710d790a45", aliceKeyPair.SecretKey.First.Text(16))
	require.Equal(t, "12b4bd11710ac1a327c74386d0229500352339a20bb33c685723791c700fb253", aliceKeyPair.SecretKey.Second.Text(16))

	rekey := NewMockPreScheme().GenerateReEncryptionKey(aliceKeyPair.SecretKey, aliceKeyPair.PublicKey)
	require.NotNil(t, rekey)

	// write to "rekey.txt"
	rekeyBytes := rekey.RawBytes()

	require.Equal(t, 128, len(rekeyBytes))
	require.NoError(t, os.WriteFile("rekey.txt", []byte(base64.StdEncoding.Strict().EncodeToString(rekeyBytes[:])), 0600))

	firstBytes := aliceKeyPair.PublicKey.First.Bytes()
	secondBytes := aliceKeyPair.PublicKey.Second.RawBytes()
	require.Equal(t, "AF/OsI1el6csnTJZ07epOCOL+nRKDJjo/p5B814seI0qQkTggOLxzjNs0iCBxA/ATvmYVoy2OKvT+xUfLgawrh//NXJ9JFMMBZtsCdGOMMDda/mW3gVqcgudYCvUW21YBR+sAy+vTabYWOF15zpge5eYekwMx/m9aE/RG2fkX2oP2KL5a1NsVml7OpFiDssib/C9bdnWYIQrIRzi3fiAOClBMioocAmaWrblAqpAiOBfN44ej01V8WPAh7hlYEWKJlZBUe0+6TmJW+K2dEEgI0HCJIzQ4K6VBAzWy2Ae9b0KQrOpypd/rwrH5DCwEggrJZHzcskav84gww34m5tztx0SEoHvap1/NFUpII+qoyp6t277+lUzCYpIsUOA4lYTCPK9mrziRzdSeU/milhxsaFSB5pBvGJKgv+b/PgECTgRJRqEuF1lRCZdwgWHQ2sPuln+UMik9SY+Ilyarb8EOCK0P9u2QCA3uLokZ8Fq2hiLlJt5jWI3SOPtqAneMFYJ", base64.StdEncoding.EncodeToString(firstBytes[:]))
	require.Equal(t, "EtvW8XMRpM9xgPs7mEvtjyHSoeZf049i6UIQAdKOT3cu1HPlSRApPrfYImE6IX6jZxrUisoFM6MpdAn6Hb/rIhQ1daopaZRN0MsG3hHZ1BCiBplhVitcfcbWQZKBVMjFLgxvEEupAY8oq5ymxdEowzA7AnX4EPl+FOtDqzILTpA=", base64.StdEncoding.EncodeToString(secondBytes[:]))
}
