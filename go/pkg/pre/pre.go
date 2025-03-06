package pre

import (
	"github.com/tuantran-genetica/human-network-crypto-lib/pkg/pre/types"
	"github.com/tuantran-genetica/human-network-crypto-lib/pkg/pre/utils"
)

// NewPreScheme creates a new instance of preScheme with generated system parameters
func NewPreScheme() *types.PreScheme {
	g1, g2, Z := utils.GenerateSystemParameters()
	systemParams := types.SystemParams{
		G1: g1,
		G2: g2,
		Z:  Z,
	}
	return &types.PreScheme{
		Client: NewClient(systemParams),
		Proxy:  NewProxy(),
		Params: systemParams,
	}
}
