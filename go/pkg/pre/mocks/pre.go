package mocks

import (
	"math/big"
	"os"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/tuantran-genetica/human-network-crypto-lib/pkg/crypto"
	"github.com/tuantran-genetica/human-network-crypto-lib/pkg/pre/types"
	"github.com/tuantran-genetica/human-network-crypto-lib/pkg/pre/utils"
)

type mockPreScheme struct {
	g1             *bn254.G1Affine
	g2             *bn254.G2Affine
	z              *bn254.GT
	Scalar         *big.Int
	AliceKeyPair   *types.KeyPair
	BobKeyPair     *types.KeyPair
	Message        string
	SymmetricKeyGT *bn254.GT
}

func NewMockPreScheme() types.PreScheme {
	g1, g2, Z := utils.GenerateSystemParameters()

	// Generate a fixed scalar for deterministic testing
	scalar := new(big.Int).SetInt64(42)

	// Generate key pairs for Alice and Bob
	aliceKeypair, err := LoadKeyPairFromFile("./mocks/alice_keypair.json")
	if err != nil {
		panic(err)
	}
	bobKeypair, err := LoadKeyPairFromFile("./mocks/bob_keypair.json")
	if err != nil {
		panic(err)
	}
	buffer, err := LoadMockData()
	if err != nil {
		panic(err)
	}

	message := string(buffer)
	// Generate a fixed symmetric key in GT for deterministic testing
	keyGT, _, _ := crypto.GenerateRandomSymmetricKeyFromGT(32)

	return &mockPreScheme{
		g1:             &g1,
		g2:             &g2,
		z:              &Z,
		Scalar:         scalar,
		AliceKeyPair:   aliceKeypair,
		BobKeyPair:     bobKeypair,
		Message:        message,
		SymmetricKeyGT: keyGT,
	}
}

// Interface implementations - using pre-computed values
func (m *mockPreScheme) GenerateReEncryptionKey(_ *types.SecretKey, _ *types.PublicKey) *bn254.G2Affine {
	// Use pre-computed values instead of parameters
	return new(bn254.G2Affine).ScalarMultiplication(m.BobKeyPair.PublicKey.Second, m.AliceKeyPair.SecretKey.First)
}

func (m *mockPreScheme) SecondLevelEncryption(_ *types.SecretKey, _ string, _ *big.Int) *types.SecondLevelCipherText {
	// Use pre-computed values instead of parameters
	first := new(bn254.G1Affine).ScalarMultiplication(m.g1, m.Scalar)
	secondTemp1 := new(bn254.GT).Exp(*m.z, m.AliceKeyPair.SecretKey.First)
	secondTemp := new(bn254.GT).Exp(*secondTemp1, m.Scalar)
	second := new(bn254.GT).Mul(m.SymmetricKeyGT, secondTemp)

	key, _ := crypto.DeriveKeyFromGT(m.SymmetricKeyGT, 32)
	encryptedMessage, _ := crypto.EncryptAESGCM(m.Message, key)

	encryptedKey := &types.SecondLevelSymmetricKey{
		First:  first,
		Second: second,
	}

	return &types.SecondLevelCipherText{
		EncryptedKey:     encryptedKey,
		EncryptedMessage: encryptedMessage,
	}
}

func (m *mockPreScheme) ReEncryption(ciphertext *types.SecondLevelCipherText, reKey *bn254.G2Affine) *types.FirstLevelCipherText {
	first, _ := bn254.Pair([]bn254.G1Affine{*ciphertext.EncryptedKey.First}, []bn254.G2Affine{*reKey})

	newEncryptedKey := &types.FirstLevelSymmetricKey{
		First:  &first,
		Second: ciphertext.EncryptedKey.Second,
	}

	return &types.FirstLevelCipherText{
		EncryptedKey:     newEncryptedKey,
		EncryptedMessage: ciphertext.EncryptedMessage,
	}
}

func (m *mockPreScheme) DecryptFirstLevel(ciphertext *types.FirstLevelCipherText, _ *types.SecretKey) string {
	// Use pre-computed Bob's secret key instead of parameter
	order := bn254.ID.ScalarField()
	temp := new(bn254.GT).Exp(*ciphertext.EncryptedKey.First, new(big.Int).ModInverse(m.BobKeyPair.SecretKey.Second, order))

	symmetricKeyGT := new(bn254.GT).Div(ciphertext.EncryptedKey.Second, temp)
	symmetricKey, _ := crypto.DeriveKeyFromGT(symmetricKeyGT, 32)

	decryptedMessage, _ := crypto.DecryptAESGCM(ciphertext.EncryptedMessage, symmetricKey)
	return decryptedMessage
}

func (m *mockPreScheme) SecretToPubkey(secret *types.SecretKey) *types.PublicKey {
	return utils.SecretToPubkey(secret, m.g2, m.z)
}

// Helper methods for testing
func (m *mockPreScheme) GetAliceKeyPair() *types.KeyPair {
	return m.AliceKeyPair
}

func (m *mockPreScheme) GetBobKeyPair() *types.KeyPair {
	return m.BobKeyPair
}

func (m *mockPreScheme) GetTestMessage() string {
	return m.Message
}

func (m *mockPreScheme) GetScalar() *big.Int {
	return m.Scalar
}

func (m *mockPreScheme) GetSymmetricKeyGT() *bn254.GT {
	return m.SymmetricKeyGT
}

func (m *mockPreScheme) G1() *bn254.G1Affine {
	return m.g1
}

func (m *mockPreScheme) G2() *bn254.G2Affine {
	return m.g2
}

func (m *mockPreScheme) Z() *bn254.GT {
	return m.z
}

func LoadMockData() ([]byte, error) {
	return os.ReadFile("./mocks/data.txt")
}
