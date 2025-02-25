package types

import (
	"bytes"

	"github.com/consensys/gnark-crypto/ecc/bn254"
)

type FirstLevelSymmetricKey struct {
	First  *bn254.GT // First component of the key in G1 group
	Second *bn254.GT // Second component of the key in GT group
}

type SecondLevelSymmetricKey struct {
	First  *bn254.G1Affine // First component of the key in G1 group
	Second *bn254.GT       // Second component of the key in GT group
}

// FirstLevelCipherText represents the first level encrypted message components
type FirstLevelCipherText struct {
	EncryptedKey     *FirstLevelSymmetricKey // The encrypted symmetric key
	EncryptedMessage []byte                  // The encrypted message, encrypted with the symmetric key
}

// SecondLevelCipherText represents the second level encrypted message components
type SecondLevelCipherText struct {
	EncryptedKey     *SecondLevelSymmetricKey // The encrypted symmetric key
	EncryptedMessage []byte                   // The encrypted message, encrypted with the symmetric key
}

// ToBytes serializes FirstLevelSymmetricKey to bytes
func (k *FirstLevelSymmetricKey) ToBytes() []byte {
	if k == nil {
		return nil
	}

	var buf bytes.Buffer
	if k.First != nil {
		firstBytes := k.First.Bytes() // [384]byte
		buf.Write(firstBytes[:])      // convert to slice
	}
	if k.Second != nil {
		secondBytes := k.Second.Bytes()
		buf.Write(secondBytes[:])
	}
	return buf.Bytes()
}

func (k *FirstLevelSymmetricKey) FromBytes(data []byte) *FirstLevelSymmetricKey {
	if k == nil {
		return nil
	}

	if len(data) == 0 {
		return nil
	}

	k.First = new(bn254.GT)
	err := k.First.SetBytes(data[:384])
	if err != nil {
		panic(err)
	}

	k.Second = new(bn254.GT)
	err = k.Second.SetBytes(data[384:])
	if err != nil {
		panic(err)
	}

	return k
}

// ToBytes serializes SecondLevelSymmetricKey to bytes
func (k *SecondLevelSymmetricKey) ToBytes() []byte {
	if k == nil {
		return nil
	}

	var buf bytes.Buffer
	if k.First != nil {
		firstBytes := k.First.Bytes()
		buf.Write(firstBytes[:])
	}
	if k.Second != nil {
		secondBytes := k.Second.Bytes()
		buf.Write(secondBytes[:])
	}
	return buf.Bytes()
}

func (k *SecondLevelSymmetricKey) FromBytes(data []byte) *SecondLevelSymmetricKey {
	if k == nil {
		return nil
	}

	if len(data) == 0 {
		return nil
	}

	k.First = new(bn254.G1Affine)
	_, err := k.First.SetBytes(data[:32])
	if err != nil {
		panic(err)
	}

	k.Second = new(bn254.GT)
	err = k.Second.SetBytes(data[32:])
	if err != nil {
		panic(err)
	}

	return k
}
