package types_test

import (
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/tuantran-genetica/human-network-crypto-lib/pkg/pre/types"
	"github.com/tuantran-genetica/human-network-crypto-lib/pkg/testutils"
)

func TestToAndFromBytes(t *testing.T) {
	firstLevelSymKey := &types.FirstLevelSymmetricKey{
		First:  testutils.GenerateRandomGTElem(),
		Second: testutils.GenerateRandomGTElem(),
	}

	firstLevelBytes := firstLevelSymKey.ToBytes()
	recoveredFirstLevelSymKey := new(types.FirstLevelSymmetricKey).FromBytes(firstLevelBytes)

	require.Equal(t, firstLevelSymKey, recoveredFirstLevelSymKey)
}

func TestToAndFromBytesSecondLevel(t *testing.T) {
	secondLevelSymKey := &types.SecondLevelSymmetricKey{
		First:  testutils.GenerateRandomG1Elem(),
		Second: testutils.GenerateRandomGTElem(),
	}

	secondLevelBytes := secondLevelSymKey.ToBytes()
	recoveredSecondLevelSymKey := new(types.SecondLevelSymmetricKey).FromBytes(secondLevelBytes)

	require.Equal(t, secondLevelSymKey, recoveredSecondLevelSymKey)
}
