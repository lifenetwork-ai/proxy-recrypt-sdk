package main

import (
	"fmt"
	"math/big"
	"math/rand"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/tuantran-genetica/human-network-crypto-lib/pkg/pre/utils"
)

func main() {
	// Generate system parameters
	g1, g2, Z := utils.GenerateSystemParameters()

	fmt.Println("System parameters generated successfully!")
	fmt.Printf("g1 (random generator in G1): %v\n", g1)
	fmt.Printf("g2 (random generator in G2): %v\n", g2)
	fmt.Printf("Z = e(g1,g2) in GT: %v\n", Z)

	// Verify the parameters with a test
	scalar := big.NewInt(rand.Int63())

	// Compute g1^a
	var gScaled bn254.G1Affine
	gJac := new(bn254.G1Jac).FromAffine(&g1)
	gJac.ScalarMultiplication(gJac, scalar)
	gScaled.FromJacobian(gJac)

	// Verify that e(g1^a,g2) = e(g1,g2)^a = Z^a, bilinearity of the pairing
	pairingResult, _ := bn254.Pair([]bn254.G1Affine{gScaled}, []bn254.G2Affine{g2})
	expectedResult := new(bn254.GT).Exp(Z, scalar)

	fmt.Println("\nVerifying correctness:")
	fmt.Printf("e(g^a,g) = %v\n", pairingResult)
	fmt.Printf("Z^a = %v\n", expectedResult)
	fmt.Printf("Equality holds: %v\n", pairingResult.Equal(expectedResult))
}
