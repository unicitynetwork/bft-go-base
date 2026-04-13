package money

import (
	"bytes"
	"fmt"

	abhash "github.com/unicitynetwork/bft-go-base/hash"
	"github.com/unicitynetwork/bft-go-base/txsystem/fc"
	"github.com/unicitynetwork/bft-go-base/types"
	"github.com/unicitynetwork/bft-go-base/types/hex"
)

var _ types.UnitData = (*BillData)(nil)

type BillData struct {
	_              struct{}      `cbor:",toarray"`
	Version        types.Version `json:"version"`
	Value          uint64        `json:"value,string"`   // The monetary value of this bill
	OwnerPredicate hex.Bytes     `json:"ownerPredicate"` // The owner predicate of this bill
	Counter        uint64        `json:"counter,string"` // The transaction counter of this bill
}

func NewUnitData(unitID types.UnitID, unitTypeExtractor types.UnitTypeExtractor) (types.UnitData, error) {
	typeID, err := unitTypeExtractor(unitID)
	if err != nil {
		return nil, fmt.Errorf("extracting unit type: %w", err)
	}

	switch typeID {
	case BillUnitType:
		return &BillData{}, nil
	case FeeCreditRecordUnitType:
		return &fc.FeeCreditRecord{}, nil
	}

	return nil, fmt.Errorf("unknown unit type in UnitID %s", unitID)
}

func NewBillData(value uint64, ownerPredicate []byte) *BillData {
	return &BillData{
		Version:        1,
		Value:          value,
		OwnerPredicate: ownerPredicate,
	}
}

func (b *BillData) Write(hasher abhash.Hasher) {
	hasher.Write(b)
}

func (b *BillData) SummaryValueInput() uint64 {
	return b.Value
}

func (b *BillData) Copy() types.UnitData {
	return &BillData{
		Value:          b.Value,
		OwnerPredicate: bytes.Clone(b.OwnerPredicate),
		Counter:        b.Counter,
	}
}

func (b *BillData) Owner() []byte {
	return b.OwnerPredicate
}

func (b *BillData) GetVersion() types.Version {
	if b != nil && b.Version != 0 {
		return b.Version
	}
	return 1
}

func (b *BillData) MarshalCBOR() ([]byte, error) {
	type alias BillData
	cp := *b
	if cp.Version == 0 {
		cp.Version = 1
	}
	return types.Cbor.Marshal((*alias)(&cp))
}

func (b *BillData) UnmarshalCBOR(data []byte) error {
	type alias BillData
	return types.UnmarshalVersioned(1, data, (*alias)(b), b)
}
