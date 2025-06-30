package money

import (
	"github.com/unicitynetwork/bft-go-base/predicates/templates"
	"github.com/unicitynetwork/bft-go-base/txsystem/fc"
	"github.com/unicitynetwork/bft-go-base/types"
)

const (
	BillUnitType            = 1
	FeeCreditRecordUnitType = 16
)

func NewFeeCreditRecordIDFromPublicKey(pdr *types.PartitionDescriptionRecord, shard types.ShardID, pubKey []byte, latestAdditionTime uint64) (types.UnitID, error) {
	ownerPredicate := templates.NewP2pkh256BytesFromKey(pubKey)
	return NewFeeCreditRecordIDFromOwnerPredicate(pdr, shard, ownerPredicate, latestAdditionTime)
}

func NewFeeCreditRecordIDFromPublicKeyHash(pdr *types.PartitionDescriptionRecord, shard types.ShardID, pubKeyHash []byte, latestAdditionTime uint64) (types.UnitID, error) {
	ownerPredicate := templates.NewP2pkh256BytesFromKeyHash(pubKeyHash)
	return NewFeeCreditRecordIDFromOwnerPredicate(pdr, shard, ownerPredicate, latestAdditionTime)
}

func NewFeeCreditRecordIDFromOwnerPredicate(pdr *types.PartitionDescriptionRecord, shard types.ShardID, ownerPredicate []byte, latestAdditionTime uint64) (types.UnitID, error) {
	return pdr.ComposeUnitID(shard, FeeCreditRecordUnitType, fc.PrndSh(ownerPredicate, latestAdditionTime))
}
