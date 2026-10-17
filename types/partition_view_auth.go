package types

import (
	"bytes"
	"crypto"
	"errors"
	"fmt"
	"slices"
)

/*
AuthenticatedPartitionView is a partition view whose commitment has been
authenticated end to end. It can only be created by AuthenticateView or
AuthenticatePartitionView and is immutable: every accessor returns copies.

Authentication means, all together:

  - the candidate view is well formed (version, bounds, 32 byte hashes,
    canonical encoding when decoded from bytes) and its leaves are exactly the
    distinct, prefix-free, complete, left-to-right ordered shards of ONE scheme;
  - the shard tree rebuilt from the exact (IR, TRHash, ShardConfHash) leaves is
    reached by the enclosing UC's partition path, for the caller's expected
    partition, and evaluates to the enclosing seal hash;
  - the enclosing UC's own IR, TRHash, configuration hash, shard and sibling
    hashes are exactly its view leaf;
  - the complete enclosing seal is authenticated by the caller's verifier
    (network, exact epoch, round at or after the epoch start, quorum).

The scheme and the configuration hashes of the view are therefore committed by
the root quorum signature and need no independent admission; an independently
pinned topology (WithPinnedTopology) is an optional, stricter policy.
*/
type AuthenticatedPartitionView struct {
	partition PartitionID
	scheme    ShardingScheme
	view      *PartitionViewV1
	tree      ShardTree
	// index maps ShardID.Key() to the leaf position: built once at authentication so that
	// per-shard accessors and lazy certificate derivation are O(1) lookups, not O(S) scans
	index map[string]int
	// onProbe is a test hook, called once per shard lookup (the scaling tests count index probes with it).
	// It is nil in production: the cost is one predictable nil check per lookup.
	onProbe func()
	// sealBytes and pathBytes are the canonical encodings of the complete seal and
	// partition path every derived UC carries
	sealBytes []byte
	pathBytes []byte
}

type authOptions struct {
	pinned *PartitionViewTopology
}

// AuthOption is an optional policy of AuthenticateView.
type AuthOption func(*authOptions)

// WithPinnedTopology additionally requires the view to have exactly the scheme
// and configuration hashes of an independently admitted topology. The pins must be
// complete: a valid scheme and a 32-byte hash for every shard, otherwise they are refused. It can only reject more, never admit what the seal does not commit to.
func WithPinnedTopology(topo PartitionViewTopology) AuthOption {
	return func(o *authOptions) {
		t := PartitionViewTopology{Scheme: slices.Clone(topo.Scheme), ShardConfHashes: map[string][]byte{}}
		for k, h := range topo.ShardConfHashes {
			t.ShardConfHashes[k] = bytes.Clone(h)
		}
		o.pinned = &t
	}
}

// AuthenticatePartitionView decodes an UNTRUSTED candidate view (bounded,
// canonical) and authenticates it, see AuthenticateView.
func AuthenticatePartitionView(candidate []byte, enclosingUC *UnicityCertificate, partition PartitionID, sealVerifier SealVerifier, algo crypto.Hash, opts ...AuthOption) (*AuthenticatedPartitionView, error) {
	view, err := DecodePartitionViewV1(candidate)
	if err != nil {
		return nil, fmt.Errorf("decoding candidate partition view: %w", err)
	}
	return AuthenticateView(view, enclosingUC, partition, sealVerifier, algo, opts...)
}

// AuthenticateView authenticates the candidate view against the enclosing UC
// and the caller's authority policy. "partition" is the caller's expected
// partition, never taken from the candidate. Nothing in the candidate is
// trusted before the seal check succeeds; neither the input view nor the UC is
// retained or modified.
func AuthenticateView(candidate *PartitionViewV1, enclosingUC *UnicityCertificate, partition PartitionID, sealVerifier SealVerifier, algo crypto.Hash, opts ...AuthOption) (*AuthenticatedPartitionView, error) {
	if sealVerifier == nil {
		return nil, ErrRootValidatorInfoMissing
	}
	if candidate == nil {
		return nil, errors.New("partition view is nil")
	}
	if enclosingUC == nil {
		return nil, ErrUnicityCertificateIsNil
	}
	var o authOptions
	for _, opt := range opts {
		opt(&o)
	}
	view := candidate.Clone() // private copy: later changes by the caller cannot reach the result
	if err := view.validateBounds(); err != nil {
		return nil, fmt.Errorf("invalid partition view: %w", err)
	}

	// the topology the candidate claims: its own leaves
	topo := PartitionViewTopology{ShardConfHashes: make(map[string][]byte, len(view.Leaves))}
	for i := range view.Leaves {
		l := &view.Leaves[i]
		if _, dup := topo.ShardConfHashes[l.ShardID.Key()]; dup {
			return nil, fmt.Errorf("shard %q appears twice in the view", l.ShardID)
		}
		topo.ShardConfHashes[l.ShardID.Key()] = l.ShardConfHash
		if l.ShardID.Length() > 0 {
			topo.Scheme = append(topo.Scheme, l.ShardID)
		}
	}
	if len(view.Leaves) == 1 && view.Leaves[0].ShardID.Length() > 0 {
		return nil, fmt.Errorf("a single shard view must be of the empty shard, got %q", view.Leaves[0].ShardID)
	}
	// distinct, prefix-free, complete, canonical order: ValidateStructure checks the leaves
	// against the canonical order of the scheme they themselves form
	tree, err := func() (ShardTree, error) {
		if o.pinned != nil {
			if err := checkCompletePins(*o.pinned); err != nil {
				return nil, err
			}
			if err := view.ValidateStructure(partition, *o.pinned); err != nil {
				return nil, fmt.Errorf("view does not match the pinned topology: %w", err)
			}
		}
		return view.VerifyTree(enclosingUC, partition, topo, algo)
	}()
	if err != nil {
		return nil, err
	}
	// only now is the seal authenticated; the tree commitment above ties the view to its hash
	if err := sealVerifier.VerifySeal(enclosingUC.UnicitySeal); err != nil {
		return nil, fmt.Errorf("authenticating unicity seal: %w", err)
	}

	sealBytes, err := enclosingUC.UnicitySeal.MarshalCBOR()
	if err != nil {
		return nil, fmt.Errorf("encoding unicity seal: %w", err)
	}
	pathBytes, err := enclosingUC.UnicityTreeCertificate.MarshalCBOR()
	if err != nil {
		return nil, fmt.Errorf("encoding unicity tree certificate: %w", err)
	}
	// the seal is derived from these bytes for every certificate: they must round-trip exactly (checked once here)
	var sealCopy UnicitySeal
	if err := sealCopy.UnmarshalCBOR(sealBytes); err != nil {
		return nil, fmt.Errorf("copying unicity seal: %w", err)
	}
	if b, err := sealCopy.MarshalCBOR(); err != nil || !bytes.Equal(b, sealBytes) {
		return nil, fmt.Errorf("unicity seal does not re-encode identically (err: %v)", err)
	}
	av := &AuthenticatedPartitionView{
		partition: partition, scheme: slices.Clone(topo.Scheme), view: view, tree: tree,
		index: leafIndex(view), sealBytes: sealBytes, pathBytes: pathBytes,
	}
	return av, nil
}

// checkCompletePins requires pins to be a complete admitted topology: a valid scheme and
// a native 32-byte configuration hash for EVERY shard of it. Missing entries are not
// "unpinned", they make the pins unusable.
func checkCompletePins(topo PartitionViewTopology) error {
	order, err := CanonicalShardOrder(topo.Scheme)
	if err != nil {
		return fmt.Errorf("pinned topology: %w", err)
	}
	for _, id := range order {
		if h := topo.ShardConfHashes[id.Key()]; len(h) != partitionViewHashLen {
			return fmt.Errorf("pinned topology: shard %q needs a %d-byte configuration hash, got %d bytes", id, partitionViewHashLen, len(h))
		}
	}
	return nil
}

// find returns the leaf position of the shard: one index probe, independent of the number of shards.
func (a *AuthenticatedPartitionView) find(shard ShardID) (int, bool) {
	if a.onProbe != nil {
		a.onProbe()
	}
	i, ok := a.index[shard.Key()]
	return i, ok
}

// leafIndex maps the shard key of every leaf to its position.
func leafIndex(v *PartitionViewV1) map[string]int {
	m := make(map[string]int, len(v.Leaves))
	for i := range v.Leaves {
		m[v.Leaves[i].ShardID.Key()] = i
	}
	return m
}

// Partition is the authenticated partition.
func (a *AuthenticatedPartitionView) Partition() PartitionID { return a.partition }

// Scheme is the authenticated sharding scheme (empty for a single shard partition).
func (a *AuthenticatedPartitionView) Scheme() ShardingScheme { return slices.Clone(a.scheme) }

// View is a copy of the authenticated view.
func (a *AuthenticatedPartitionView) View() *PartitionViewV1 { return a.view.Clone() }

// Seal is a copy of the complete authenticated seal.
func (a *AuthenticatedPartitionView) Seal() *UnicitySeal {
	var s UnicitySeal
	_ = s.UnmarshalCBOR(a.sealBytes) // produced by MarshalCBOR of the authenticated seal
	return &s
}

// SealBytes is a copy of the canonical encoding of the complete authenticated seal.
func (a *AuthenticatedPartitionView) SealBytes() []byte { return bytes.Clone(a.sealBytes) }

// ShardConfHashes are the configuration hashes committed by the seal, by shard.
func (a *AuthenticatedPartitionView) ShardConfHashes() map[string][]byte {
	m := make(map[string][]byte, len(a.view.Leaves))
	for _, l := range a.view.Leaves {
		m[l.ShardID.Key()] = bytes.Clone(l.ShardConfHash)
	}
	return m
}

// ShardConfHash returns the committed configuration hash of the shard.
func (a *AuthenticatedPartitionView) ShardConfHash(shard ShardID) ([]byte, bool) {
	if i, ok := a.find(shard); ok {
		return bytes.Clone(a.view.Leaves[i].ShardConfHash), true
	}
	return nil, false
}

// Topology is the authenticated topology, suitable as the (now authenticated)
// policy of the per shard body checks.
func (a *AuthenticatedPartitionView) Topology() PartitionViewTopology {
	return PartitionViewTopology{Scheme: a.Scheme(), ShardConfHashes: a.ShardConfHashes()}
}

// Certificate derives the ordinary version 1 unicity certificate of the shard. It is derived
// lazily from the one authenticated tree: O(dS) tree path work plus the certificate bytes, independent of the
// number of other shards.
func (a *AuthenticatedPartitionView) Certificate(shard ShardID) (*UnicityCertificate, error) {
	if i, ok := a.find(shard); ok {
		return a.certificate(i)
	}
	return nil, fmt.Errorf("shard %q is not in the authenticated view", shard)
}

// Certificates derives the ordinary certificate of every shard, in canonical
// order. Each carries copies of the complete seal and the partition path.
func (a *AuthenticatedPartitionView) Certificates() ([]*UnicityCertificate, error) {
	ucs := make([]*UnicityCertificate, len(a.view.Leaves))
	for i := range ucs {
		uc, err := a.certificate(i)
		if err != nil {
			return nil, err
		}
		ucs[i] = uc
	}
	return ucs, nil
}

func (a *AuthenticatedPartitionView) certificate(i int) (*UnicityCertificate, error) {
	l := a.view.Leaves[i].Clone()
	stc, err := a.tree.Certificate(l.ShardID)
	if err != nil {
		return nil, fmt.Errorf("shard tree certificate of %q: %w", l.ShardID, err)
	}
	// the tree hands out its own hash slices (shared between the paths of different
	// shards): every returned certificate gets private copies
	siblings := make([][]byte, len(stc.SiblingHashes))
	for i, h := range stc.SiblingHashes {
		siblings[i] = bytes.Clone(h)
	}
	stc.SiblingHashes = siblings
	seal, utc := &UnicitySeal{}, &UnicityTreeCertificate{}
	if err := seal.UnmarshalCBOR(a.sealBytes); err != nil {
		return nil, fmt.Errorf("copying unicity seal: %w", err)
	}
	if err := utc.UnmarshalCBOR(a.pathBytes); err != nil {
		return nil, fmt.Errorf("copying unicity tree certificate: %w", err)
	}
	return &UnicityCertificate{
		Version: 1, InputRecord: l.InputRecord, TRHash: l.TRHash, ShardConfHash: l.ShardConfHash,
		ShardTreeCertificate: stc, UnicityTreeCertificate: utc, UnicitySeal: seal,
	}, nil
}
