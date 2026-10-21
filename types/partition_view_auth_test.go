package types

import (
	"bytes"
	"crypto"
	"fmt"
	"slices"
	"testing"

	"github.com/stretchr/testify/require"

	testsig "github.com/unicitynetwork/bft-go-base/testutils/sig"
)

func pvAuth(f *pvFixture, opts ...AuthOption) (*AuthenticatedPartitionView, error) {
	enc, err := f.view.MarshalCBOR()
	if err != nil {
		return nil, err
	}
	return AuthenticatePartitionView(enc, f.uc, pvTestPartition, TrustBaseSealVerifier(f.tb), crypto.SHA256, opts...)
}

// The view of an untrusted candidate is authenticated without any independently
// admitted topology: the scheme and every configuration hash are committed by the seal.
func TestAuthenticatePartitionView_NoPinnedTopology(t *testing.T) {
	for _, bits := range []int{0, 1, 2, 3} {
		t.Run(fmt.Sprintf("%d shards", 1<<bits), func(t *testing.T) {
			scheme := pvScheme(bits)
			topo := pvTopology(scheme)
			f := pvEnclose(t, pvView(t, scheme), topo)
			av, err := pvAuth(f)
			require.NoError(t, err)
			require.Equal(t, pvTestPartition, av.Partition())
			require.Len(t, av.Scheme(), len(scheme)%(1<<bits+1))
			for id, h := range topo.ShardConfHashes {
				got := av.ShardConfHashes()[id]
				require.Equal(t, h, got)
			}
			ucs, err := av.Certificates()
			require.NoError(t, err)
			require.Len(t, ucs, 1<<bits)
			want, err := f.uc.MarshalCBOR()
			require.NoError(t, err)
			got, err := ucs[0].MarshalCBOR()
			require.NoError(t, err)
			require.Equal(t, want, got)
			for i, uc := range ucs {
				l := f.view.Leaves[i]
				require.NoError(t, uc.Verify(f.tb, crypto.SHA256, pvTestPartition, l.ShardID, l.ShardConfHash))
				single, err := av.Certificate(l.ShardID)
				require.NoError(t, err)
				sb, _ := single.MarshalCBOR()
				ub, _ := uc.MarshalCBOR()
				require.Equal(t, ub, sb)
			}
			// the authenticated seal is the complete enclosing seal
			sb, err := f.uc.UnicitySeal.MarshalCBOR()
			require.NoError(t, err)
			require.Equal(t, sb, av.SealBytes())
			_, err = av.Certificate(ShardID{bits: []byte{0xff}, length: 8})
			require.Error(t, err)
		})
	}
}

func TestAuthenticateView_RejectsForgedCandidates(t *testing.T) {
	scheme := pvScheme(2)
	topo := pvTopology(scheme)
	f := pvEnclose(t, pvView(t, scheme), topo)
	verifier := TrustBaseSealVerifier(f.tb)
	auth := func(v *PartitionViewV1, uc *UnicityCertificate) error {
		_, err := AuthenticateView(v, uc, pvTestPartition, verifier, crypto.SHA256)
		return err
	}
	require.NoError(t, auth(f.view, f.uc))

	t.Run("structure of the claimed scheme", func(t *testing.T) {
		for name, mod := range map[string]func(v *PartitionViewV1){
			"missing shard":     func(v *PartitionViewV1) { v.Leaves = v.Leaves[:3] },
			"duplicate shard":   func(v *PartitionViewV1) { v.Leaves[1] = v.Leaves[0] },
			"reordered":         func(v *PartitionViewV1) { v.Leaves[0], v.Leaves[1] = v.Leaves[1], v.Leaves[0] },
			"overlapping":       func(v *PartitionViewV1) { v.Leaves[1].ShardID = ShardID{bits: []byte{0}, length: 1} },
			"deeper shard":      func(v *PartitionViewV1) { v.Leaves[1].ShardID = ShardID{bits: []byte{0x40}, length: 3} },
			"wrong partition":   func(v *PartitionViewV1) { v.PartitionID++ },
			"short config hash": func(v *PartitionViewV1) { v.Leaves[2].ShardConfHash = v.Leaves[2].ShardConfHash[:31] },
			"short TR hash":     func(v *PartitionViewV1) { v.Leaves[2].TRHash = nil },
			"nil input record":  func(v *PartitionViewV1) { v.Leaves[2].InputRecord = nil },
			"zero version":      func(v *PartitionViewV1) { v.Version = 0 },
			"empty shard among": func(v *PartitionViewV1) { v.Leaves[0].ShardID = ShardID{} },
		} {
			v := f.view.Clone()
			mod(v)
			require.Error(t, auth(v, f.uc), name)
		}
		// a single non empty shard is no partition
		one := &PartitionViewV1{Version: 1, PartitionID: pvTestPartition, Leaves: f.view.Clone().Leaves[:1]}
		require.Error(t, auth(one, f.uc))
	})

	t.Run("a self consistent forged vector cannot reach the seal", func(t *testing.T) {
		// attacker builds a complete valid view with other records and keeps the genuine UC
		forged := pvView(t, scheme)
		forged.Leaves[3].InputRecord.Hash = pvHash("attacker state")
		forged.Leaves[3].InputRecord.PreviousHash = pvHash("attacker prev")
		require.Error(t, auth(forged, f.uc))
		// ... or a different scheme with the genuine seal
		other := pvView(t, pvScheme(1))
		require.Error(t, auth(other, f.uc))
		// ... or the genuine vector paired with another tree's seal hash
		uc := *f.uc
		seal := *f.uc.UnicitySeal
		seal.Hash = pvHash("other root")
		uc.UnicitySeal = &seal
		require.Error(t, auth(f.view, &uc))
	})

	t.Run("enclosing UC must be exactly its leaf", func(t *testing.T) {
		for name, mod := range map[string]func(uc *UnicityCertificate){
			"input record": func(uc *UnicityCertificate) { ir := *uc.InputRecord; ir.Timestamp++; uc.InputRecord = &ir },
			"TR hash":      func(uc *UnicityCertificate) { uc.TRHash = pvHash("x") },
			"config hash":  func(uc *UnicityCertificate) { uc.ShardConfHash = pvHash("x") },
			"siblings": func(uc *UnicityCertificate) {
				st := uc.ShardTreeCertificate
				st.SiblingHashes = [][]byte{pvHash("a"), pvHash("b")}
				uc.ShardTreeCertificate = st
			},
			"shard not in view": func(uc *UnicityCertificate) {
				st := uc.ShardTreeCertificate
				st.Shard = ShardID{bits: []byte{0x80}, length: 1}
				uc.ShardTreeCertificate = st
			},
		} {
			uc := *f.uc
			mod(&uc)
			require.Error(t, auth(f.view, &uc), name)
		}
	})

	t.Run("nil partition path elements never reach native evaluation", func(t *testing.T) {
		uc := *f.uc
		utc := *f.uc.UnicityTreeCertificate
		utc.HashSteps = []*PathItem{nil}
		uc.UnicityTreeCertificate = &utc
		require.NotPanics(t, func() { require.Error(t, auth(f.view, &uc)) })
		utc.HashSteps = append([]*PathItem{nil}, f.uc.UnicityTreeCertificate.HashSteps...)
		require.NotPanics(t, func() { require.Error(t, auth(f.view, &uc)) })
		uc.UnicityTreeCertificate = nil
		require.NotPanics(t, func() { require.Error(t, auth(f.view, &uc)) })
		uc.UnicityTreeCertificate = f.uc.UnicityTreeCertificate
		uc.UnicitySeal = nil
		require.NotPanics(t, func() { require.Error(t, auth(f.view, &uc)) })
		require.Error(t, auth(nil, f.uc))
		require.Error(t, auth(f.view, nil))
	})

	t.Run("expected partition comes from the caller", func(t *testing.T) {
		_, err := AuthenticateView(f.view, f.uc, pvTestPartition+1, verifier, crypto.SHA256)
		require.Error(t, err)
	})
}

// Seals which are correctly signed but outside the authority context are not accepted.
func TestAuthenticateView_AuthorityContext(t *testing.T) {
	scheme := pvScheme(1)
	topo := pvTopology(scheme)
	view := pvView(t, scheme)

	signer, verifier := testsig.CreateSignerAndVerifier(t)
	sigKey, err := verifier.MarshalPublicKey()
	require.NoError(t, err)
	newTB := func(net NetworkID, epoch, start uint64) RootTrustBase {
		tb, err := NewTrustBase(net, []*NodeInfo{{NodeID: "test", SigKey: sigKey, Stake: 1}}, WithEpoch(epoch), WithEpochStart(start))
		require.NoError(t, err)
		return tb
	}
	tree, err := CreateShardTree(topo.Scheme, view.treeInputs(), crypto.SHA256)
	require.NoError(t, err)
	ut, err := NewUnicityTree(crypto.SHA256, []*UnicityTreeData{{Partition: pvTestPartition, ShardTreeRoot: tree.RootHash()}, {Partition: 0x01010101, ShardTreeRoot: pvHash("o")}})
	require.NoError(t, err)
	utc, err := ut.Certificate(pvTestPartition)
	require.NoError(t, err)
	stc, err := tree.Certificate(view.Leaves[0].ShardID)
	require.NoError(t, err)
	uc := func(net NetworkID, epoch, round uint64) *UnicityCertificate {
		seal := &UnicitySeal{Version: 1, NetworkID: net, Epoch: epoch, RootChainRoundNumber: round, Timestamp: NewTimestamp(), PreviousHash: pvHash("p"), Hash: ut.RootHash()}
		require.NoError(t, seal.Sign("test", signer))
		l := view.Leaves[0]
		return &UnicityCertificate{Version: 1, InputRecord: l.InputRecord, TRHash: l.TRHash, ShardConfHash: l.ShardConfHash, ShardTreeCertificate: stc, UnicityTreeCertificate: utc, UnicitySeal: seal}
	}
	tb := newTB(NetworkMainNet, 3, 50)
	auth := func(u *UnicityCertificate, v SealVerifier) error {
		_, err := AuthenticateView(view, u, pvTestPartition, v, crypto.SHA256)
		return err
	}
	good := TrustBaseSealVerifier(tb)
	require.NoError(t, auth(uc(NetworkMainNet, 3, 50), good))
	require.ErrorContains(t, auth(uc(NetworkMainNet+1, 3, 60), good), "network")
	require.ErrorContains(t, auth(uc(NetworkMainNet, 2, 60), good), "epoch")
	require.ErrorContains(t, auth(uc(NetworkMainNet, 4, 60), good), "epoch")
	require.ErrorContains(t, auth(uc(NetworkMainNet, 3, 49), good), "before the start")
	// end boundary when the authenticated history provides it
	until := TrustBaseSealVerifierUntil(tb, 100)
	require.NoError(t, auth(uc(NetworkMainNet, 3, 99), until))
	require.ErrorContains(t, auth(uc(NetworkMainNet, 3, 100), until), "end of epoch")
	require.NoError(t, auth(uc(NetworkMainNet, 3, 1000), good), "no boundary known: not enforced")
	// another authority (same keys are not enough, the quorum must verify)
	_, other := testsig.CreateSignerAndVerifier(t)
	otherKey, _ := other.MarshalPublicKey()
	otherTB, err := NewTrustBase(NetworkMainNet, []*NodeInfo{{NodeID: "test", SigKey: otherKey, Stake: 1}}, WithEpoch(3), WithEpochStart(50))
	require.NoError(t, err)
	require.ErrorContains(t, auth(uc(NetworkMainNet, 3, 60), TrustBaseSealVerifier(otherTB)), "authenticating unicity seal")
	// a verifier is required
	_, err = AuthenticateView(view, uc(NetworkMainNet, 3, 60), pvTestPartition, nil, crypto.SHA256)
	require.ErrorIs(t, err, ErrRootValidatorInfoMissing)
	// no nonsense verifier success is cached by the library: failures stay failures
	rejecting := sealVerifierFunc(func(*UnicitySeal) error { return fmt.Errorf("no") })
	require.Error(t, auth(uc(NetworkMainNet, 3, 60), rejecting))
}

type sealVerifierFunc func(*UnicitySeal) error

func (f sealVerifierFunc) VerifySeal(s *UnicitySeal) error { return f(s) }

func TestAuthenticatePartitionView_UntrustedBytes(t *testing.T) {
	scheme := pvScheme(2)
	f := pvEnclose(t, pvView(t, scheme), pvTopology(scheme))
	good, err := f.view.MarshalCBOR()
	require.NoError(t, err)
	verifier := TrustBaseSealVerifier(f.tb)
	auth := func(b []byte) error {
		_, err := AuthenticatePartitionView(b, f.uc, pvTestPartition, verifier, crypto.SHA256)
		return err
	}
	require.NoError(t, auth(good))
	require.Error(t, auth(good[:len(good)-1]))
	require.Error(t, auth(append(bytes.Clone(good), 0)))
	require.Error(t, auth(nil))
	require.Error(t, auth(make([]byte, MaxPartitionViewBytes+1)))
	noncanon := append([]byte{0x83, 0x18, 0x01}, good[2:]...)
	require.Error(t, auth(noncanon))
}

func TestAuthenticatedPartitionView_PinnedTopologyIsStricter(t *testing.T) {
	scheme := pvScheme(2)
	topo := pvTopology(scheme)
	f := pvEnclose(t, pvView(t, scheme), topo)
	_, err := pvAuth(f, WithPinnedTopology(topo))
	require.NoError(t, err)

	// a genuinely authenticated view may still be refused by the pins
	wrong := pvTopology(scheme)
	wrong.ShardConfHashes[scheme[2].Key()] = pvHash("another configuration")
	_, err = pvAuth(f, WithPinnedTopology(wrong))
	require.ErrorContains(t, err, "pinned topology")
	_, err = pvAuth(f, WithPinnedTopology(pvTopology(pvScheme(3))))
	require.ErrorContains(t, err, "pinned topology")
	_, err = pvAuth(f, WithPinnedTopology(pvTopology(ShardingScheme{})))
	require.ErrorContains(t, err, "pinned topology")
	// pins cannot admit what the seal does not commit to
	forged := pvView(t, scheme)
	forged.Leaves[1].ShardConfHash = pvHash("forged")
	pinForged := pvTopology(scheme)
	pinForged.ShardConfHashes[scheme[1].Key()] = pvHash("forged")
	enc, err := forged.MarshalCBOR()
	require.NoError(t, err)
	_, err = AuthenticatePartitionView(enc, f.uc, pvTestPartition, TrustBaseSealVerifier(f.tb), crypto.SHA256, WithPinnedTopology(pinForged))
	require.Error(t, err)

	// the legacy entry point is the pinned policy over the same machinery
	_, err = f.view.AssembleCertificates(f.uc, pvTestPartition, topo, TrustBaseSealVerifier(f.tb), crypto.SHA256)
	require.NoError(t, err)
}

func TestAuthenticatedPartitionView_IsImmutable(t *testing.T) {
	scheme := pvScheme(2)
	topo := pvTopology(scheme)
	f := pvEnclose(t, pvView(t, scheme), topo)
	view := f.view.Clone()
	uc, err := cloneUC(f.uc)
	require.NoError(t, err)
	av, err := AuthenticateView(view, uc, pvTestPartition, TrustBaseSealVerifier(f.tb), crypto.SHA256, WithPinnedTopology(topo))
	require.NoError(t, err)
	before, err := av.Certificates()
	require.NoError(t, err)
	beforeBytes, _ := before[1].MarshalCBOR()

	// changes to the inputs after authentication do not reach the object
	view.Leaves[1].InputRecord.Hash[0] ^= 0xff
	view.Leaves[1].TRHash[0] ^= 0xff
	uc.UnicitySeal.Hash[0] ^= 0xff
	uc.UnicityTreeCertificate.HashSteps[0].Hash[0] ^= 0xff
	topo.ShardConfHashes[scheme[1].Key()][0] ^= 0xff
	// ... nor do changes to anything it returned
	got := av.View()
	got.Leaves[1].InputRecord.Hash[0] ^= 0xff
	av.Scheme()[0] = ShardID{}
	av.ShardConfHashes()[scheme[1].Key()][0] ^= 0xff
	av.Seal().Hash[0] ^= 0xff
	av.SealBytes()[0] ^= 0xff
	h, _ := av.ShardConfHash(scheme[1])
	h[0] ^= 0xff
	before[1].InputRecord.Hash[0] ^= 0xff
	before[1].UnicitySeal.Hash[0] ^= 0xff

	after, err := av.Certificates()
	require.NoError(t, err)
	afterBytes, _ := after[1].MarshalCBOR()
	require.Equal(t, beforeBytes, afterBytes)
	for _, u := range after {
		require.NoError(t, u.Verify(f.tb, crypto.SHA256, pvTestPartition, u.ShardTreeCertificate.Shard, u.ShardConfHash))
	}
	// derived certificates do not share memory with each other
	after[0].UnicitySeal.Hash[0] ^= 0xff
	require.NotEqual(t, after[0].UnicitySeal.Hash, after[1].UnicitySeal.Hash)
}

// Returned certificates never alias the authenticated object nor each other, including
// the sibling hashes which the shard tree shares between the paths of different shards.
func TestAuthenticatedPartitionView_ReturnedPathsDoNotAlias(t *testing.T) {
	scheme := pvScheme(2)
	topo := pvTopology(scheme)
	f := pvEnclose(t, pvView(t, scheme), topo)
	av, err := pvAuth(f)
	require.NoError(t, err)

	golden, err := av.Certificates()
	require.NoError(t, err)
	goldenBytes := make([][]byte, len(golden))
	for i, uc := range golden {
		goldenBytes[i], err = uc.MarshalCBOR()
		require.NoError(t, err)
	}
	verifyAll := func() {
		t.Helper()
		ucs, err := av.Certificates()
		require.NoError(t, err)
		for i, uc := range ucs {
			b, err := uc.MarshalCBOR()
			require.NoError(t, err)
			require.Equal(t, goldenBytes[i], b, "shard %d", i)
			require.NoError(t, uc.Verify(f.tb, crypto.SHA256, pvTestPartition, uc.ShardTreeCertificate.Shard, uc.ShardConfHash))
		}
	}

	// mutate every sibling hash of every certificate of a first derivation
	first, err := av.Certificates()
	require.NoError(t, err)
	for _, uc := range first {
		for _, h := range uc.ShardTreeCertificate.SiblingHashes {
			for i := range h {
				h[i] ^= 0xff
			}
		}
		uc.ShardTreeCertificate.Shard = ShardID{}
	}
	verifyAll()

	// single certificates, mutated, then derived again
	c1, err := av.Certificate(scheme[0])
	require.NoError(t, err)
	c1.ShardTreeCertificate.SiblingHashes[0][0] ^= 0xff
	c1.ShardTreeCertificate.SiblingHashes[1][0] ^= 0xff
	c2, err := av.Certificate(scheme[0])
	require.NoError(t, err)
	require.NotEqual(t, c1.ShardTreeCertificate.SiblingHashes[0], c2.ShardTreeCertificate.SiblingHashes[0])
	verifyAll()

	// hashes shared by the paths of different shards (the sibling subtree of 00 is the node 01's
	// path ends with, both lead to the other half "1"): mutating one certificate cannot change another
	a, _ := av.Certificate(scheme[0])
	b, _ := av.Certificate(scheme[1])
	require.Equal(t, a.ShardTreeCertificate.SiblingHashes[1], b.ShardTreeCertificate.SiblingHashes[1], "same committed hash")
	a.ShardTreeCertificate.SiblingHashes[1][0] ^= 0xff
	require.NotEqual(t, a.ShardTreeCertificate.SiblingHashes[1], b.ShardTreeCertificate.SiblingHashes[1])
	verifyAll()
	require.NoError(t, b.Verify(f.tb, crypto.SHA256, pvTestPartition, scheme[1], topo.ShardConfHashes[scheme[1].Key()]))

	// and the enclosing certificate the caller passed in does not share its paths either
	f.uc.ShardTreeCertificate.SiblingHashes[0][0] ^= 0xff
	verifyAll()
}

// Pins must be complete: a missing entry is not "unpinned".
func TestAuthenticateView_PinsMustBeComplete(t *testing.T) {
	scheme := pvScheme(2)
	topo := pvTopology(scheme)
	f := pvEnclose(t, pvView(t, scheme), topo)
	clonePins := func() PartitionViewTopology {
		c := PartitionViewTopology{Scheme: slices.Clone(topo.Scheme), ShardConfHashes: map[string][]byte{}}
		for k, v := range topo.ShardConfHashes {
			c.ShardConfHashes[k] = bytes.Clone(v)
		}
		return c
	}
	_, err := pvAuth(f, WithPinnedTopology(clonePins()))
	require.NoError(t, err)

	missing := clonePins()
	delete(missing.ShardConfHashes, scheme[2].Key())
	empty := clonePins()
	empty.ShardConfHashes = map[string][]byte{}
	nilMap := clonePins()
	nilMap.ShardConfHashes = nil
	short := clonePins()
	short.ShardConfHashes[scheme[1].Key()] = short.ShardConfHashes[scheme[1].Key()][:31]
	emptyHash := clonePins()
	emptyHash.ShardConfHashes[scheme[3].Key()] = []byte{}
	long := clonePins()
	long.ShardConfHashes[scheme[0].Key()] = append(long.ShardConfHashes[scheme[0].Key()], 0)
	incomplete := clonePins()
	incomplete.Scheme = incomplete.Scheme[:3]
	overlapping := clonePins()
	overlapping.Scheme = append(overlapping.Scheme, ShardID{bits: []byte{0}, length: 1})
	empties := PartitionViewTopology{}
	for name, pins := range map[string]PartitionViewTopology{
		"missing entry": missing, "empty map": empty, "nil map": nilMap, "short hash": short,
		"empty hash": emptyHash, "long hash": long, "incomplete scheme": incomplete, "overlapping scheme": overlapping,
		"zero value pins": empties,
	} {
		_, err := pvAuth(f, WithPinnedTopology(pins))
		require.ErrorContains(t, err, "pinned topology", name)
	}
	// single shard pins are complete with the empty shard's hash
	one := pvEnclose(t, pvView(t, ShardingScheme{}), pvTopology(ShardingScheme{}))
	_, err = pvAuth(one, WithPinnedTopology(pvTopology(ShardingScheme{})))
	require.NoError(t, err)
	_, err = pvAuth(one, WithPinnedTopology(PartitionViewTopology{ShardConfHashes: map[string][]byte{}}))
	require.ErrorContains(t, err, "pinned topology")
}

// A typed nil trust base (a lookup which returned a nil *RootTrustBaseV1) is "no trust base", not a panic
// (bft-go-base#12).
func TestTrustBaseSealVerifier_TypedNilTrustBase(t *testing.T) {
	var tb *RootTrustBaseV1
	seal := &UnicitySeal{Version: 1, NetworkID: NetworkMainNet, Epoch: 1}
	require.NotPanics(t, func() {
		require.ErrorIs(t, TrustBaseSealVerifier(tb).VerifySeal(seal), ErrRootValidatorInfoMissing)
		require.ErrorIs(t, TrustBaseSealVerifierUntil(tb, 100).VerifySeal(seal), ErrRootValidatorInfoMissing)
		require.ErrorIs(t, TrustBaseSealVerifier(nil).VerifySeal(seal), ErrRootValidatorInfoMissing)
		require.ErrorIs(t, TrustBaseSealVerifier(tb).VerifySeal(nil), ErrRootValidatorInfoMissing)
	})
}

// cloneUC is an independent copy of the certificate (CBOR round trip).
func cloneUC(uc *UnicityCertificate) (*UnicityCertificate, error) {
	b, err := uc.MarshalCBOR()
	if err != nil {
		return nil, fmt.Errorf("encoding unicity certificate: %w", err)
	}
	var c UnicityCertificate
	if err := c.UnmarshalCBOR(b); err != nil {
		return nil, fmt.Errorf("copying unicity certificate: %w", err)
	}
	return &c, nil
}
