package mocks

import (
	"encoding/base64"
	"math/big"
	"os"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/tuantran-genetica/human-network-crypto-lib/pkg/crypto"
	"github.com/tuantran-genetica/human-network-crypto-lib/pkg/pre/types"
	"github.com/tuantran-genetica/human-network-crypto-lib/pkg/pre/utils"
)

type MockPreScheme struct {
	g1             *bn254.G1Affine
	g2             *bn254.G2Affine
	z              *bn254.GT
	ReKey          *bn254.G2Affine
	Scalar         *big.Int
	AliceKeyPair   *types.KeyPair
	BobKeyPair     *types.KeyPair
	Message        []byte
	SymmetricKeyGT *bn254.GT
	SymmetricKey   []byte
}

func NewMockPreScheme() types.PreScheme {
	g1, g2, Z := utils.GenerateSystemParameters()

	// Generate key pairs for Alice and Bob
	aliceKeypair, err := LoadKeyPairFromFile("../../testdata/alice_keypair.json")
	if err != nil {
		panic(err)
	}
	bobKeypair, err := LoadKeyPairFromFile("../../testdata/bob_keypair.json")
	if err != nil {
		panic(err)
	}

	reKeyBase64FromFile, err := os.ReadFile("../../testdata/rekey.txt")
	if err != nil {
		panic(err)
	}
	rekeyBytes, err := base64.StdEncoding.DecodeString(string(reKeyBase64FromFile))
	if err != nil {
		panic(err)
	}

	rekey := new(bn254.G2Affine)
	rekey.SetBytes(rekeyBytes)

	message, err := os.ReadFile("../../testdata/data.txt")
	if err != nil {
		panic(err)
	}

	scalar, err := LoadMockScalar()
	if err != nil {
		panic(err)
	}

	symmetricKeyGtContent, err := os.ReadFile("../../testdata/symmetric_key_gt.txt")
	if err != nil {
		panic(err)
	}

	symmetricKeyGtBytes, err := base64.StdEncoding.DecodeString(string(symmetricKeyGtContent))
	if err != nil {
		panic(err)
	}
	symmetricKeyGt := new(bn254.GT)
	err = symmetricKeyGt.SetBytes(symmetricKeyGtBytes)
	if err != nil {
		panic(err)
	}

	key, _ := crypto.DeriveKeyFromGT(symmetricKeyGt, 32)

	return &MockPreScheme{
		g1:             &g1,
		g2:             &g2,
		z:              &Z,
		ReKey:          rekey,
		Scalar:         scalar,
		AliceKeyPair:   aliceKeypair,
		BobKeyPair:     bobKeypair,
		Message:        message,
		SymmetricKeyGT: symmetricKeyGt,
		SymmetricKey:   key,
	}
}

// Interface implementations - using pre-computed values
func (m *MockPreScheme) GenerateReEncryptionKey(_ *types.SecretKey, _ *types.PublicKey) *bn254.G2Affine {
	// Use pre-computed values instead of parameters
	return new(bn254.G2Affine).ScalarMultiplication(m.BobKeyPair.PublicKey.Second, m.AliceKeyPair.SecretKey.First)
}

func (m *MockPreScheme) SecondLevelEncryption(_ *types.SecretKey, _ string, _ *big.Int) *types.SecondLevelCipherText {
	// Use pre-computed values instead of parameters
	first := new(bn254.G1Affine).ScalarMultiplication(m.g1, m.Scalar)
	secondTemp1 := new(bn254.GT).Exp(*m.z, m.AliceKeyPair.SecretKey.First)
	secondTemp := new(bn254.GT).Exp(*secondTemp1, m.Scalar)
	second := new(bn254.GT).Mul(m.SymmetricKeyGT, secondTemp)

	keyGTBytes := m.SymmetricKeyGT.Bytes()

	// write to mocks folder if not exists
	err := utils.WriteAsBase64IfNotExists("./mocks/symmetric_key_gt.txt", keyGTBytes[:])
	if err != nil {
		panic(err)
	}
	utils.WriteAsBase64IfNotExists("./mocks/symmetric_key.txt", m.SymmetricKey)
	if err != nil {
		panic(err)
	}

	encryptedMessage, _ := crypto.EncryptAESGCM(m.Message, m.SymmetricKey)
	err = utils.WriteAsBase64IfNotExists("./mocks/encrypted_message.txt", encryptedMessage)
	if err != nil {
		panic(err)
	}
	encryptedKey := &types.SecondLevelSymmetricKey{
		First:  first,
		Second: second,
	}

	return &types.SecondLevelCipherText{
		EncryptedKey:     encryptedKey,
		EncryptedMessage: encryptedMessage,
	}
}

func (m *MockPreScheme) ReEncryption(ciphertext *types.SecondLevelCipherText, reKey *bn254.G2Affine) *types.FirstLevelCipherText {
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

func (m *MockPreScheme) DecryptFirstLevel(ciphertext *types.FirstLevelCipherText, _ *types.SecretKey) string {
	// Use pre-computed Bob's secret key instead of parameter
	order := bn254.ID.ScalarField()
	temp := new(bn254.GT).Exp(*ciphertext.EncryptedKey.First, new(big.Int).ModInverse(m.BobKeyPair.SecretKey.Second, order))

	symmetricKeyGT := new(bn254.GT).Div(ciphertext.EncryptedKey.Second, temp)
	symmetricKey, _ := crypto.DeriveKeyFromGT(symmetricKeyGT, 32)

	decryptedMessage, _ := crypto.DecryptAESGCM(ciphertext.EncryptedMessage, symmetricKey)
	return string(decryptedMessage)
}

func (m *MockPreScheme) SecretToPubkey(secret *types.SecretKey) *types.PublicKey {
	return utils.SecretToPubkey(secret, m.g2, m.z)
}

// Helper methods for testing
func (m *MockPreScheme) GetAliceKeyPair() *types.KeyPair {
	return m.AliceKeyPair
}

func (m *MockPreScheme) GetBobKeyPair() *types.KeyPair {
	return m.BobKeyPair
}

func (m *MockPreScheme) GetTestMessage() []byte {
	return m.Message
}

func (m *MockPreScheme) GetScalar() *big.Int {
	return m.Scalar
}

func (m *MockPreScheme) GetSymmetricKeyGT() *bn254.GT {
	return m.SymmetricKeyGT
}

func (m *MockPreScheme) G1() *bn254.G1Affine {
	return m.g1
}

func (m *MockPreScheme) G2() *bn254.G2Affine {
	return m.g2
}

func (m *MockPreScheme) Z() *bn254.GT {
	return m.z
}

func LoadMockScalar() (*big.Int, error) {
	mockData, err := os.ReadFile("../../testdata/random_scalar.txt")
	if err != nil {
		return nil, err
	}
	decodedBytes, err := base64.StdEncoding.DecodeString(string(mockData))
	if err != nil {
		return nil, err
	}
	return new(big.Int).SetBytes(decodedBytes), nil
}
