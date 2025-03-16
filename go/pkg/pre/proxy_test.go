package pre_test

import (
	"testing"

	"github.com/tuantran-genetica/human-network-crypto-lib/pkg/pre"
	"github.com/tuantran-genetica/human-network-crypto-lib/pkg/testutils"
)

func BenchmarkReEncryption(b *testing.B) {
	scheme := pre.NewPreScheme()
	cipherText := testutils.GenerateMockSecondLevelCipherText(500)
	reKey := testutils.GenerateRandomG2Elem()
	for n := 0; n < b.N; n++ {
		scheme.Proxy.ReEncryption(cipherText, reKey)
	}
}
