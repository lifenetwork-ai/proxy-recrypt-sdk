package main

import (
	"fmt"

	"github.com/tuantran-genetica/human-network-crypto-lib/pkg/pre/mocks"
)

// Example usage function
func main() {
	// Save a new keypair
	err := mocks.SaveKeyPairToFile("test_keypair.json")
	if err != nil {
		fmt.Printf("Failed to save keypair: %v\n", err)
		return
	}

	// Load the keypair
	_, err = mocks.LoadKeyPairFromFile("test_keypair.json")
	if err != nil {
		fmt.Printf("Failed to load keypair: %v\n", err)
		return
	}

	fmt.Println("Successfully loaded keypair!")
}
