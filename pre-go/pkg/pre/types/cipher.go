package types

import (
	"bytes"
	"encoding/hex"
	"fmt"

	"github.com/consensys/gnark-crypto/ecc/bn254"
)

type FirstLevelSymmetricKey struct {
	First  *bn254.GT `json:"first"`  // First component of the key in GT group
	Second *bn254.GT `json:"second"` // Second component of the key in GT group
}

type SecondLevelSymmetricKey struct {
	First  *bn254.G1Affine `json:"first"`  // First component of the key in G1 group
	Second *bn254.GT       `json:"second"` // Second component of the key in GT group
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

// String returns hex encoded string representation
func (k *FirstLevelSymmetricKey) String() string {
	if k == nil {
		return ""
	}
	return hex.EncodeToString(k.ToBytes())
}

// FromString decodes hex string into FirstLevelSymmetricKey
func (k *FirstLevelSymmetricKey) FromString(s string) error {
	if k == nil {
		return fmt.Errorf("nil receiver")
	}
	if s == "" {
		return nil
	}

	data, err := hex.DecodeString(s)
	if err != nil {
		return fmt.Errorf("failed to decode hex string: %w", err)
	}

	if len(data) != 768 { // 384 bytes for each GT element
		return fmt.Errorf("invalid data length for FirstLevelSymmetricKey: expected 768, got %d", len(data))
	}

	k.FromBytes(data)
	return nil
}

// String returns hex encoded string representation
func (k *SecondLevelSymmetricKey) String() string {
	if k == nil {
		return ""
	}
	return hex.EncodeToString(k.ToBytes())
}

// FromString decodes hex string into SecondLevelSymmetricKey
func (k *SecondLevelSymmetricKey) FromString(s string) error {
	if k == nil {
		return fmt.Errorf("nil receiver")
	}
	if s == "" {
		return nil
	}

	data, err := hex.DecodeString(s)
	if err != nil {
		return fmt.Errorf("failed to decode hex string: %w", err)
	}

	if len(data) != 416 {
		return fmt.Errorf("invalid data length for SecondLevelSymmetricKey: expected 416, got %d", len(data))
	}

	k.FromBytes(data)
	return nil
}
