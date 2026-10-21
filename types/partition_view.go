package types

import (
	"bytes"
	"crypto"
	"errors"
	"fmt"
	"reflect"
	"slices"

	"github.com/fxamacker/cbor/v2"
)

/*
Partition view: the complete vector of shard tree leaves of one partition, as
committed by a single unicity seal. It is an untagged, explicitly versioned
array

	[1, partitionId, [[shardId, inputRecord, trHash, shardConfHash], ...]]

from which ordinary version 1 unicity certificates of every shard of the
partition can be reconstructed.
*/

// PartitionViewVersionV1 is the only supported partition view version.
const PartitionViewVersionV1 Version = 1

// Consolidation admission limits of the partition view V1 (not consensus rules).
const (
	// MaxPartitionViewLeaves is the maximum number of shards in a view.
	MaxPartitionViewLeaves = 8
	// MaxPartitionViewBytes is the maximum size of the encoded view.
	MaxPartitionViewBytes = 16 * 1024
	// MaxPartitionViewShardIDBits is the maximum shard ID length in bits.
	MaxPartitionViewShardIDBits = 256
	// MaxPartitionViewIRBytes is the maximum size of an encoded input record.
	MaxPartitionViewIRBytes = 1024
	// MaxPartitionViewSummaryValueBytes is the maximum size of IR summary value.
	MaxPartitionViewSummaryValueBytes = 256

	partitionViewHashLen = 32
	// the largest nested array is the input record (10 items); the leaf
	// vector is limited separately by MaxPartitionViewLeaves.
	partitionViewMaxArrayElements = 16
	partitionViewMaxNestedLevels  = 4
)

type PartitionViewV1 struct {
	_           struct{} `cbor:",toarray"`
	Version     Version
	PartitionID PartitionID
	Leaves      []PartitionViewLeafV1
}

type PartitionViewLeafV1 struct {
	_             struct{} `cbor:",toarray"`
	ShardID       ShardID
	InputRecord   *InputRecord
	TRHash        []byte
	ShardConfHash []byte
}

var partitionViewDecMode = func() cbor.DecMode {
	m, err := cbor.DecOptions{
		DupMapKey:         cbor.DupMapKeyEnforcedAPF,
		IndefLength:       cbor.IndefLengthForbidden,
		MaxNestedLevels:   partitionViewMaxNestedLevels,
		MaxArrayElements:  partitionViewMaxArrayElements,
		MaxMapPairs:       partitionViewMaxArrayElements,
		ExtraReturnErrors: cbor.ExtraDecErrorUnknownField,
	}.DecMode()
	if err != nil {
		panic(fmt.Errorf("creating partition view CBOR decoder: %w", err))
	}
	return m
}()

// partitionViewRaw drops the codec methods of PartitionViewV1 to avoid recursive calls. The leaf type has no
// codec methods, so it needs no such alias.
type partitionViewRaw PartitionViewV1

/*
MarshalCBOR encodes the view. The version is never defaulted and the view
must satisfy the structural bounds.
*/
func (v PartitionViewV1) MarshalCBOR() ([]byte, error) {
	if err := v.validateBounds(); err != nil {
		return nil, fmt.Errorf("invalid partition view: %w", err)
	}
	data, err := Cbor.Marshal(partitionViewRaw(v))
	if err != nil {
		return nil, fmt.Errorf("encoding partition view: %w", err)
	}
	if len(data) > MaxPartitionViewBytes {
		return nil, fmt.Errorf("encoded partition view is %d bytes, limit is %d", len(data), MaxPartitionViewBytes)
	}
	return data, nil
}

/*
UnmarshalCBOR strictly decodes the view: bounded input size, exact array
lengths, no trailing bytes, no indefinite length items, explicit version 1,
and rejects any encoding which differs from the canonical one.
*/
func (v *PartitionViewV1) UnmarshalCBOR(data []byte) error {
	if len(data) > MaxPartitionViewBytes {
		return fmt.Errorf("partition view is %d bytes, limit is %d", len(data), MaxPartitionViewBytes)
	}
	var raw partitionViewRaw
	if err := partitionViewDecMode.Unmarshal(data, &raw); err != nil {
		return fmt.Errorf("decoding partition view: %w", err)
	}
	if raw.Version != PartitionViewVersionV1 {
		return fmt.Errorf("unsupported partition view version %d", raw.Version)
	}
	if err := PartitionViewV1(raw).validateBounds(); err != nil {
		return fmt.Errorf("invalid partition view: %w", err)
	}
	canonical, err := Cbor.Marshal(raw)
	if err != nil {
		return fmt.Errorf("re-encoding partition view: %w", err)
	}
	if !bytes.Equal(canonical, data) {
		return errors.New("partition view is not canonically encoded")
	}
	*v = PartitionViewV1(raw)
	return nil
}

// DecodePartitionViewV1 decodes and strictly validates the encoded view.
func DecodePartitionViewV1(data []byte) (*PartitionViewV1, error) {
	v := &PartitionViewV1{}
	if err := v.UnmarshalCBOR(data); err != nil {
		return nil, err
	}
	return v, nil
}

// Clone returns deep copy of the view; nil and empty byte slices are preserved.
func (v *PartitionViewV1) Clone() *PartitionViewV1 {
	if v == nil {
		return nil
	}
	c := &PartitionViewV1{Version: v.Version, PartitionID: v.PartitionID}
	if v.Leaves != nil {
		c.Leaves = make([]PartitionViewLeafV1, len(v.Leaves))
		for i := range v.Leaves {
			c.Leaves[i] = v.Leaves[i].Clone()
		}
	}
	return c
}

// Clone returns deep copy of the leaf.
func (l PartitionViewLeafV1) Clone() PartitionViewLeafV1 {
	return PartitionViewLeafV1{
		ShardID:       ShardID{bits: slices.Clone(l.ShardID.bits), length: l.ShardID.length},
		InputRecord:   cloneIR(l.InputRecord),
		TRHash:        slices.Clone(l.TRHash),
		ShardConfHash: slices.Clone(l.ShardConfHash),
	}
}

func cloneIR(ir *InputRecord) *InputRecord {
	if ir == nil {
		return nil
	}
	c := *ir
	c.PreviousHash = slices.Clone(ir.PreviousHash)
	c.Hash = slices.Clone(ir.Hash)
	c.SummaryValue = slices.Clone(ir.SummaryValue)
	c.BlockHash = slices.Clone(ir.BlockHash)
	c.ETHash = slices.Clone(ir.ETHash)
	return &c
}

// validateBounds checks version, partition and the per leaf limits; it does
// not know the expected topology.
func (v PartitionViewV1) validateBounds() error {
	if v.Version != PartitionViewVersionV1 {
		return fmt.Errorf("unsupported partition view version %d", v.Version)
	}
	if v.PartitionID == 0 {
		return errors.New("partition ID is zero")
	}
	if n := len(v.Leaves); n < 1 || n > MaxPartitionViewLeaves {
		return fmt.Errorf("leaf count must be 1..%d, got %d", MaxPartitionViewLeaves, n)
	}
	for i := range v.Leaves {
		if err := v.Leaves[i].validateBounds(); err != nil {
			return fmt.Errorf("leaf %d: %w", i, err)
		}
	}
	return nil
}

func (l PartitionViewLeafV1) validateBounds() error {
	if l.ShardID.length > MaxPartitionViewShardIDBits {
		return fmt.Errorf("shard ID is %d bits, limit is %d", l.ShardID.length, MaxPartitionViewShardIDBits)
	}
	if err := l.InputRecord.IsValid(); err != nil {
		return fmt.Errorf("input record: %w", err)
	}
	ir := l.InputRecord
	if len(ir.SummaryValue) > MaxPartitionViewSummaryValueBytes {
		return fmt.Errorf("summary value is %d bytes, limit is %d", len(ir.SummaryValue), MaxPartitionViewSummaryValueBytes)
	}
	// a fixed slice, not a map: the first malformed field reported is deterministic and no map is allocated per leaf
	for _, f := range [...]struct {
		name string
		hash []byte
	}{
		{"state hash", ir.Hash}, {"previous hash", ir.PreviousHash}, {"block hash", ir.BlockHash}, {"executed transactions hash", ir.ETHash},
	} {
		// absent/empty (initial state, unchanged state) or a full hash
		if n := len(f.hash); n != 0 && n != partitionViewHashLen {
			return fmt.Errorf("%s must be empty or %d bytes, got %d", f.name, partitionViewHashLen, n)
		}
	}
	irBytes, err := ir.MarshalCBOR()
	if err != nil {
		return fmt.Errorf("encoding input record: %w", err)
	}
	if len(irBytes) > MaxPartitionViewIRBytes {
		return fmt.Errorf("input record is %d bytes, limit is %d", len(irBytes), MaxPartitionViewIRBytes)
	}
	if n := len(l.TRHash); n != partitionViewHashLen {
		return fmt.Errorf("TRHash must be %d bytes, got %d", partitionViewHashLen, n)
	}
	if n := len(l.ShardConfHash); n != partitionViewHashLen {
		return fmt.Errorf("ShardConfHash must be %d bytes, got %d", partitionViewHashLen, n)
	}
	return nil
}

/*
PartitionViewTopology is the trusted description of the partition the view is
validated against. It must come from the verifier's own configuration, never
from the response carrying the view.
*/
type PartitionViewTopology struct {
	// Scheme is the sharding scheme of the partition (empty for single shard).
	Scheme ShardingScheme
	// ShardConfHashes are the admitted shard configuration hashes by
	// ShardID.Key(). Entries which are present must match the view; assembly
	// of certificates requires an entry for every shard.
	ShardConfHashes map[string][]byte
}

/*
CanonicalShardOrder returns the shard IDs of the (complete, prefix-free)
scheme in binary tree left-to-right order (lexicographic bit string, "0" before
"1"). Empty scheme yields the single empty shard ID.
*/
func CanonicalShardOrder(scheme ShardingScheme) ([]ShardID, error) {
	if len(scheme) > MaxPartitionViewLeaves {
		return nil, fmt.Errorf("scheme has %d shards, limit is %d", len(scheme), MaxPartitionViewLeaves)
	}
	return canonicalShardOrder(scheme, compareShardIDs)
}

func canonicalShardOrder(scheme ShardingScheme, cmp func(a, b ShardID) int) ([]ShardID, error) {
	sorted, err := scheme.sortedValid(cmp)
	if err != nil {
		return nil, fmt.Errorf("invalid sharding scheme: %w", err)
	}
	// validation (prefix-free and complete) already produced the canonical (left-to-right) order
	ids := slices.Collect(sorted.All())
	for _, id := range ids {
		if id.length > MaxPartitionViewShardIDBits {
			return nil, fmt.Errorf("shard ID %s is longer than %d bits", id, MaxPartitionViewShardIDBits)
		}
	}
	return ids, nil
}

/*
ValidateStructure checks that the view is a well formed view of the given
partition and exactly the shards of the topology, in canonical order. It does
not touch any hash tree.
*/
func (v *PartitionViewV1) ValidateStructure(partition PartitionID, topo PartitionViewTopology) error {
	if v == nil {
		return errors.New("partition view is nil")
	}
	if err := v.validateBounds(); err != nil {
		return fmt.Errorf("invalid partition view: %w", err)
	}
	if v.PartitionID != partition {
		return fmt.Errorf("partition view is for partition %s, expected %s", v.PartitionID, partition)
	}
	order, err := CanonicalShardOrder(topo.Scheme)
	if err != nil {
		return err
	}
	if len(v.Leaves) != len(order) {
		return fmt.Errorf("view has %d leaves, topology has %d shards", len(v.Leaves), len(order))
	}
	for i, id := range order {
		l := &v.Leaves[i]
		if !l.ShardID.Equal(id) {
			return fmt.Errorf("leaf %d is shard %q, expected %q", i, l.ShardID, id)
		}
		if h, ok := topo.ShardConfHashes[id.Key()]; ok && !bytes.Equal(h, l.ShardConfHash) {
			return fmt.Errorf("shard %q: configuration hash does not match the admitted configuration", id)
		}
	}
	return nil
}

// treeInputs converts the leaves to shard tree input, keeping the view order.
func (v *PartitionViewV1) treeInputs() []ShardTreeInput {
	in := make([]ShardTreeInput, len(v.Leaves))
	for i := range v.Leaves {
		l := &v.Leaves[i]
		in[i] = ShardTreeInput{Shard: l.ShardID, IR: l.InputRecord, TRHash: l.TRHash, ShardConfHash: l.ShardConfHash}
	}
	return in
}

/*
BuildShardTree validates the structure of the view against the topology and
builds the native shard tree from its leaves.
*/
func (v *PartitionViewV1) BuildShardTree(partition PartitionID, topo PartitionViewTopology, algo crypto.Hash) (ShardTree, error) {
	if err := v.ValidateStructure(partition, topo); err != nil {
		return nil, err
	}
	tree, err := CreateShardTree(topo.Scheme, v.treeInputs(), algo)
	if err != nil {
		return nil, fmt.Errorf("creating shard tree: %w", err)
	}
	return tree, nil
}

/*
VerifyTree checks that the view hashes into the unicity seal of the enclosing
UC: structure and topology are validated, the partition certificate of the UC
must be for the view's partition and the rebuilt shard tree root must evaluate
through it to the seal hash. The UC's own shard leaf must match the view
completely. The seal signatures are NOT checked here (see AssembleCertificates).

Returns the rebuilt shard tree.
*/
func (v *PartitionViewV1) VerifyTree(enclosingUC *UnicityCertificate, partition PartitionID, topo PartitionViewTopology, algo crypto.Hash) (ShardTree, error) {
	if enclosingUC == nil {
		return nil, ErrUnicityCertificateIsNil
	}
	if enclosingUC.UnicityTreeCertificate == nil {
		return nil, ErrUnicityTreeCertificateIsNil
	}
	if enclosingUC.UnicitySeal == nil {
		return nil, ErrUnicitySealIsNil
	}
	tree, err := v.BuildShardTree(partition, topo, algo)
	if err != nil {
		return nil, err
	}
	if enclosingUC.UnicityTreeCertificate.Partition != v.PartitionID {
		return nil, fmt.Errorf("enclosing UC is for partition %s, view is for %s",
			enclosingUC.UnicityTreeCertificate.Partition, v.PartitionID)
	}
	for i, step := range enclosingUC.UnicityTreeCertificate.HashSteps {
		if step == nil {
			return nil, fmt.Errorf("unicity tree certificate hash step %d is nil", i)
		}
	}
	utRoot, err := enclosingUC.UnicityTreeCertificate.EvalAuthPath(tree.RootHash(), algo)
	if err != nil {
		return nil, fmt.Errorf("evaluating unicity tree certificate: %w", err)
	}
	if !bytes.Equal(utRoot, enclosingUC.UnicitySeal.Hash) {
		return nil, fmt.Errorf("view does not match the seal: tree root %X, seal hash %X", utRoot, enclosingUC.UnicitySeal.Hash)
	}

	// the enclosing UC's own leaf and native shard path
	own := enclosingUC.ShardTreeCertificate.Shard
	idx := slices.IndexFunc(v.Leaves, func(l PartitionViewLeafV1) bool { return l.ShardID.Equal(own) })
	if idx < 0 {
		return nil, fmt.Errorf("enclosing UC shard %q is not in the view", own)
	}
	leaf := &v.Leaves[idx]
	if err := enclosingUC.IsValid(v.PartitionID, leaf.ShardID, leaf.ShardConfHash); err != nil {
		return nil, fmt.Errorf("enclosing UC: %w", err)
	}
	if eq, err := EqualIR(enclosingUC.InputRecord, leaf.InputRecord); err != nil || !eq {
		return nil, fmt.Errorf("enclosing UC input record does not match the view leaf (err: %v)", err)
	}
	if !bytes.Equal(enclosingUC.TRHash, leaf.TRHash) {
		return nil, errors.New("enclosing UC TRHash does not match the view leaf")
	}
	ownCert, err := tree.Certificate(own)
	if err != nil {
		return nil, fmt.Errorf("shard certificate of enclosing UC shard: %w", err)
	}
	if !slices.EqualFunc(ownCert.SiblingHashes, enclosingUC.ShardTreeCertificate.SiblingHashes, bytes.Equal) {
		return nil, errors.New("enclosing UC shard tree certificate does not match the view")
	}
	return tree, nil
}

/*
SealVerifier authenticates a unicity seal (signatures, network, epoch) against
the verifier's trusted authority. Implementations decide the trust policy and
may memoize.
*/
type SealVerifier interface {
	VerifySeal(seal *UnicitySeal) error
}

/*
TrustBaseSealVerifier adapts a root trust base to SealVerifier. Besides the
quorum signatures it enforces the authority context of the trust base: the
seal must be of the same network and epoch and must not predate the epoch start.
*/
func TrustBaseSealVerifier(tb RootTrustBase) SealVerifier {
	return trustBaseSealVerifier{tb: normalizeTrustBase(tb)}
}

/*
TrustBaseSealVerifierUntil is TrustBaseSealVerifier with the end boundary of
the epoch: the seal round must be below "nextEpochStart", the start round of the
next epoch as given by an authenticated trust base history. Pass the boundary
only when the history provides it; an absent boundary does not prove freshness.
*/
func TrustBaseSealVerifierUntil(tb RootTrustBase, nextEpochStart uint64) SealVerifier {
	return trustBaseSealVerifier{tb: normalizeTrustBase(tb), end: nextEpochStart}
}

// normalizeTrustBase turns a typed nil (a nil pointer in a non-nil interface, ie a trust base lookup which
// returned a nil *RootTrustBaseV1) into a nil interface, so that VerifySeal returns ErrRootValidatorInfoMissing
// instead of panicking in the trust base getters.
func normalizeTrustBase(tb RootTrustBase) RootTrustBase {
	if tb == nil {
		return nil
	}
	if rv := reflect.ValueOf(tb); rv.Kind() == reflect.Pointer && rv.IsNil() {
		return nil
	}
	return tb
}

type trustBaseSealVerifier struct {
	tb RootTrustBase
	// end is the exclusive end round of the epoch, zero if unknown
	end uint64
}

func (v trustBaseSealVerifier) VerifySeal(seal *UnicitySeal) error {
	if v.tb == nil {
		return ErrRootValidatorInfoMissing
	}
	if seal == nil {
		return ErrUnicitySealIsNil
	}
	if seal.NetworkID != v.tb.GetNetworkID() {
		return fmt.Errorf("seal is of network %d, trust base is of network %d", seal.NetworkID, v.tb.GetNetworkID())
	}
	if seal.Epoch != v.tb.GetEpoch() {
		return fmt.Errorf("seal is of epoch %d, trust base is of epoch %d", seal.Epoch, v.tb.GetEpoch())
	}
	if seal.RootChainRoundNumber < v.tb.GetEpochStart() {
		return fmt.Errorf("seal round %d is before the start of epoch %d (round %d)",
			seal.RootChainRoundNumber, v.tb.GetEpoch(), v.tb.GetEpochStart())
	}
	if v.end != 0 && seal.RootChainRoundNumber >= v.end {
		return fmt.Errorf("seal round %d is at or after the end of epoch %d (next epoch starts at round %d)",
			seal.RootChainRoundNumber, v.tb.GetEpoch(), v.end)
	}
	return seal.Verify(v.tb)
}

/*
AssembleCertificates derives the ordinary version 1 unicity certificate of
every shard in the view, in canonical order, under an independently PINNED
topology: the topology must carry the admitted configuration hash of every
shard. It is the stricter policy of AuthenticateView (WithPinnedTopology) and
returns the certificates of the authenticated view.
*/
func (v *PartitionViewV1) AssembleCertificates(enclosingUC *UnicityCertificate, partition PartitionID, topo PartitionViewTopology, sealVerifier SealVerifier, algo crypto.Hash) ([]*UnicityCertificate, error) {
	order, err := CanonicalShardOrder(topo.Scheme)
	if err != nil {
		return nil, err
	}
	for _, id := range order {
		if h, ok := topo.ShardConfHashes[id.Key()]; !ok || len(h) != partitionViewHashLen {
			return nil, fmt.Errorf("shard %q: admitted configuration hash is required", id)
		}
	}
	av, err := AuthenticateView(v, enclosingUC, partition, sealVerifier, algo, WithPinnedTopology(topo))
	if err != nil {
		return nil, err
	}
	return av.Certificates()
}
