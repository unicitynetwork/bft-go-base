package orchestration

import (
	abhash "github.com/unicitynetwork/bft-go-base/hash"
	"github.com/unicitynetwork/bft-go-base/types"
)

var _ types.UnitData = (*VarData)(nil)

// VarData Validator Assignment Record Data
type VarData struct {
	_           struct{}      `cbor:",toarray"`
	Version     types.Version `json:"version"`
	EpochNumber uint64        // epoch number from the validator assignment record
}

func (b *VarData) Write(hasher abhash.Hasher) {
	hasher.Write(b)
}

func (b *VarData) SummaryValueInput() uint64 {
	return 0 // no summary value checks in orchestration partition
}

func (b *VarData) Copy() types.UnitData {
	return &VarData{
		EpochNumber: b.EpochNumber,
	}
}

func (b *VarData) Owner() []byte {
	return nil
}

func (b *VarData) GetVersion() types.Version {
	if b != nil && b.Version != 0 {
		return b.Version
	}
	return 1
}

func NewVarData(epochNumber uint64) *VarData {
	return &VarData{Version: 1, EpochNumber: epochNumber}
}

func (b *VarData) MarshalCBOR() ([]byte, error) {
	type alias VarData
	cp := *b
	if cp.Version == 0 {
		cp.Version = 1
	}
	return types.Cbor.Marshal((*alias)(&cp))
}

func (b *VarData) UnmarshalCBOR(data []byte) error {
	type alias VarData
	return types.UnmarshalVersioned(1, data, (*alias)(b), b)
}
