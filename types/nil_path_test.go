package types

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/unicitynetwork/bft-go-base/tree/imt"
	"github.com/unicitynetwork/bft-go-base/tree/mt"

	abcrypto "github.com/unicitynetwork/bft-go-base/crypto"
	testsig "github.com/unicitynetwork/bft-go-base/testutils/sig"
	"github.com/unicitynetwork/bft-go-base/types/hex"
)

// A CBOR null inside a decoded slice of pointers is a nil entry. Everything on the verification path must answer
// it with an error, not a nil pointer dereference (bft-go-base#17).

type ucFix struct {
	uc        *UnicityCertificate
	tb        RootTrustBase
	partition PartitionID
	shard     ShardID
	conf      []byte
}

// newUCFix builds a signed UC of a two shard partition inside a unicity tree of two partitions (so that the
// partition path has a hash step).
func newUCFix(t testing.TB) *ucFix {
	t.Helper()
	sid0, sid1 := ShardID{}.Split()
	const partition PartitionID = 0x0f0f0f0f
	conf0 := bytes.Repeat([]byte{1}, 32)
	conf1 := bytes.Repeat([]byte{2}, 32)
	ir := func(r uint64) *InputRecord {
		return &InputRecord{Version: 1, PreviousHash: []byte{0, 0, 1}, Hash: []byte{0, 0, 2}, BlockHash: []byte{0, 0, 3},
			SummaryValue: []byte{0, 0, 4}, Timestamp: 1731504540, RoundNumber: r}
	}
	tr0, tr1 := bytes.Repeat([]byte{10}, 32), bytes.Repeat([]byte{11}, 32)
	sTree, err := CreateShardTree(ShardingScheme{sid0, sid1}, []ShardTreeInput{
		{Shard: sid0, IR: ir(1), TRHash: tr0, ShardConfHash: conf0},
		{Shard: sid1, IR: ir(2), TRHash: tr1, ShardConfHash: conf1},
	}, crypto.SHA256)
	require.NoError(t, err)
	ut, err := NewUnicityTree(crypto.SHA256, []*UnicityTreeData{
		{Partition: partition, ShardTreeRoot: sTree.RootHash()},
		{Partition: 0x01010101, ShardTreeRoot: bytes.Repeat([]byte{7}, 32)},
	})
	require.NoError(t, err)
	utCert, err := ut.Certificate(partition)
	require.NoError(t, err)
	require.NotEmpty(t, utCert.HashSteps, "the fixture needs a partition path")
	stCert, err := sTree.Certificate(sid0)
	require.NoError(t, err)

	key := sha256.Sum256([]byte("nil path fixture key"))
	signer, err := abcrypto.NewInMemorySecp256K1SignerFromKey(key[:])
	require.NoError(t, err)
	verifier, err := signer.Verifier()
	require.NoError(t, err)
	pub, err := verifier.MarshalPublicKey()
	require.NoError(t, err)
	tb, err := NewTrustBase(NetworkMainNet, []*NodeInfo{{NodeID: "test", SigKey: pub, Stake: 1}})
	require.NoError(t, err)
	seal := &UnicitySeal{Version: 1, RootChainRoundNumber: 1, Timestamp: 1731504540, PreviousHash: bytes.Repeat([]byte{3}, 32), Hash: ut.RootHash()}
	require.NoError(t, seal.Sign("test", signer))
	return &ucFix{
		uc: &UnicityCertificate{Version: 1, InputRecord: ir(1), TRHash: tr0, ShardConfHash: conf0,
			ShardTreeCertificate: stCert, UnicityTreeCertificate: utCert, UnicitySeal: seal},
		tb: tb, partition: partition, shard: sid0, conf: conf0,
	}
}

// reencode puts the UC through real CBOR, as a peer message does.
func reencode(t testing.TB, uc *UnicityCertificate) *UnicityCertificate {
	t.Helper()
	b, err := uc.MarshalCBOR()
	require.NoError(t, err)
	var out UnicityCertificate
	require.NoError(t, out.UnmarshalCBOR(b))
	return &out
}

func TestNilHashStep_VerifyReturnsAnErrorForDecodedCBORNull(t *testing.T) {
	f := newUCFix(t)
	require.NoError(t, f.uc.Verify(f.tb, crypto.SHA256, f.partition, f.shard, f.conf), "control")
	real := f.uc.UnicityTreeCertificate.HashSteps

	for name, steps := range map[string][]*PathItem{
		"only a null":      {nil},
		"null after valid": append(append([]*PathItem(nil), real...), nil),
		"null before":      append([]*PathItem{nil}, real...),
		"many nulls":       {nil, nil, nil},
	} {
		t.Run(name, func(t *testing.T) {
			uc := *f.uc
			utc := *f.uc.UnicityTreeCertificate
			utc.HashSteps = steps
			uc.UnicityTreeCertificate = &utc
			decoded := reencode(t, &uc) // a null entry survives the wire as a nil pointer
			require.Contains(t, decoded.UnicityTreeCertificate.HashSteps, (*PathItem)(nil))

			require.NotPanics(t, func() {
				err := decoded.Verify(f.tb, crypto.SHA256, f.partition, f.shard, f.conf)
				require.ErrorIs(t, err, ErrNilPathItem)
				require.ErrorIs(t, decoded.IsValid(f.partition, f.shard, f.conf), ErrNilPathItem)
				require.ErrorIs(t, decoded.UnicityTreeCertificate.IsValid(f.partition), ErrNilPathItem)
				// callers which skip IsValid are covered too
				_, err = decoded.UnicityTreeCertificate.EvalAuthPath(bytes.Repeat([]byte{1}, 32), crypto.SHA256)
				require.ErrorIs(t, err, ErrNilPathItem)
			})
		})
	}
	// the self-consistent shape of the report: a junk signature, no quorum needed
	uc := *f.uc
	utc := *f.uc.UnicityTreeCertificate
	utc.HashSteps = []*PathItem{nil}
	uc.UnicityTreeCertificate = &utc
	seal := *f.uc.UnicitySeal
	seal.Signatures = SignatureMap{"x": []byte{1}}
	uc.UnicitySeal = &seal
	require.NotPanics(t, func() { require.Error(t, reencode(t, &uc).Verify(f.tb, crypto.SHA256, f.partition, f.shard, f.conf)) })
}

func TestNilPathItems_OnTheVerificationPath(t *testing.T) {
	t.Run("EvalAuthPath of a nil certificate", func(t *testing.T) {
		var utc *UnicityTreeCertificate
		_, err := utc.EvalAuthPath(nil, crypto.SHA256)
		require.ErrorIs(t, err, ErrUnicityTreeCertificateIsNil)
	})
	t.Run("PathItem conversions", func(t *testing.T) {
		require.Nil(t, (*PathItem)(nil).ToIMTPathItem())
		_, err := NewPathItem(nil)
		require.ErrorIs(t, err, ErrNilPathItem)
		_, err = NewPathItems([]*imt.PathItem{nil})
		require.ErrorIs(t, err, ErrNilPathItem)
	})
	t.Run("indexed merkle path", func(t *testing.T) {
		good := imt.NewPathItem([]byte{1}, []byte{2})
		_, err := imt.IndexTreeOutput([]*imt.PathItem{nil}, []byte{1}, crypto.SHA256)
		require.ErrorIs(t, err, imt.ErrNilPathItem)
		_, err = imt.IndexTreeOutput([]*imt.PathItem{good, nil}, []byte{1}, crypto.SHA256)
		require.ErrorIs(t, err, imt.ErrNilPathItem)
	})
	t.Run("plain merkle path", func(t *testing.T) {
		_, err := mt.PlainTreeOutput([]*mt.PathItem{nil}, []byte{1}, crypto.SHA256)
		require.ErrorIs(t, err, mt.ErrNilPathItem)
		_, err = mt.PlainTreeOutput([]*mt.PathItem{{Hash: []byte{1}}, nil}, []byte{1}, crypto.SHA256)
		require.ErrorIs(t, err, mt.ErrNilPathItem)
	})
	t.Run("shard tree certificate without IsValid", func(t *testing.T) {
		f := newUCFix(t)
		_, err := f.uc.ShardTreeCertificate.ComputeCertificateHash(nil, f.uc.TRHash, f.conf, crypto.SHA256)
		require.ErrorIs(t, err, ErrInputRecordIsNil)
		// sibling hashes without shard ID bits would index outside the (nil) bits
		bad := ShardTreeCertificate{Version: 1, SiblingHashes: [][]byte{{1}}}
		require.NotPanics(t, func() {
			_, err := bad.ComputeCertificateHash(f.uc.InputRecord, f.uc.TRHash, f.conf, crypto.SHA256)
			require.Error(t, err)
		})
		short := f.uc.ShardTreeCertificate
		short.SiblingHashes = nil
		require.NotPanics(t, func() {
			_, err := short.ComputeCertificateHash(f.uc.InputRecord, f.uc.TRHash, f.conf, crypto.SHA256)
			require.Error(t, err)
		})
	})
	t.Run("input record", func(t *testing.T) {
		var ir *InputRecord
		_, err := ir.MarshalCBOR()
		require.ErrorIs(t, err, ErrInputRecordIsNil)
		_, err = EqualIR(nil, &InputRecord{Version: 1})
		require.Error(t, err)
		require.ErrorIs(t, AssertEqualIR(nil, &InputRecord{}), ErrInputRecordIsNil)
		require.ErrorIs(t, AssertEqualIR(&InputRecord{}, nil), ErrInputRecordIsNil)
	})
	t.Run("UC with missing parts", func(t *testing.T) {
		f := newUCFix(t)
		for name, mut := range map[string]func(*UnicityCertificate){
			"no input record":      func(uc *UnicityCertificate) { uc.InputRecord = nil },
			"no seal":              func(uc *UnicityCertificate) { uc.UnicitySeal = nil },
			"no unicity tree cert": func(uc *UnicityCertificate) { uc.UnicityTreeCertificate = nil },
		} {
			uc := *f.uc
			mut(&uc)
			require.NotPanics(t, func() { require.Error(t, uc.Verify(f.tb, crypto.SHA256, f.partition, f.shard, f.conf), name) }, name)
		}
		var nilUC *UnicityCertificate
		require.NotPanics(t, func() { require.Error(t, nilUC.Verify(f.tb, crypto.SHA256, f.partition, f.shard, f.conf)) })
	})
}

func TestNilEntries_InTrustBaseAndValidators(t *testing.T) {
	_, verifier := testsig.CreateSignerAndVerifier(t)
	key, err := verifier.MarshalPublicKey()
	require.NoError(t, err)
	good := &NodeInfo{NodeID: "a", SigKey: key, Stake: 1}

	_, err = NewTrustBase(NetworkMainNet, []*NodeInfo{good, nil})
	require.Error(t, err)

	// a trust base decoded with a null root node: the node never votes and nothing dereferences it
	tb := &RootTrustBaseV1{Version: 1, NetworkID: NetworkMainNet, Epoch: 1, RootNodes: []*NodeInfo{nil, good, nil}, QuorumThreshold: 1}
	require.NotPanics(t, func() {
		require.Error(t, tb.VerifyQuorumSignatures([]byte("x"), map[string]hex.Bytes{"a": {1}, "": {1}, "zz": {1}}))
		_, err := tb.VerifySignature([]byte("x"), []byte{1}, "b")
		require.Error(t, err)
	})
	_, err = (*NodeInfo)(nil).SigVerifier()
	require.Error(t, err)

	pdr := &PartitionDescriptionRecord{Validators: []*NodeInfo{nil, good}}
	require.NotPanics(t, func() {
		require.Nil(t, pdr.FindValidator("zz"))
		require.Equal(t, good, pdr.FindValidator("a"))
	})
}

func TestNilEntries_InPartitionViewAndProofs(t *testing.T) {
	t.Run("view leaf with a null input record", func(t *testing.T) {
		sid0, sid1 := ShardID{}.Split()
		v := &PartitionViewV1{Version: 1, PartitionID: 7, Leaves: []PartitionViewLeafV1{
			{ShardID: sid0, InputRecord: nil, TRHash: bytes.Repeat([]byte{1}, 32), ShardConfHash: bytes.Repeat([]byte{2}, 32)},
			{ShardID: sid1, InputRecord: nil, TRHash: bytes.Repeat([]byte{1}, 32), ShardConfHash: bytes.Repeat([]byte{2}, 32)},
		}}
		topo := PartitionViewTopology{Scheme: ShardingScheme{sid0, sid1}, ShardConfHashes: map[string][]byte{}}
		require.NotPanics(t, func() {
			require.Error(t, v.ValidateStructure(7, topo))
			_, err := v.BuildShardTree(7, topo, crypto.SHA256)
			require.Error(t, err)
		})
	})
	t.Run("transaction proof chain item", func(t *testing.T) {
		proof := &TxRecordProof{TxRecord: &TransactionRecord{Version: 1}, TxProof: &TxProof{Version: 1, Chain: []*GenericChainItem{nil}}}
		require.NotPanics(t, func() { require.Error(t, VerifyTxInclusion(proof, nil, crypto.SHA256)) })
	})
	t.Run("unit state proof", func(t *testing.T) {
		u := &UnitStateProof{}
		require.NotPanics(t, func() {
			_, _, err := u.CalculateStateTreeOutput(crypto.SHA256)
			require.Error(t, err)
		})
		u = &UnitStateProof{UnitTreeCert: &UnitTreeCert{}, StateTreeCert: &StateTreeCert{Path: []*StateTreePathItem{nil}}}
		require.NotPanics(t, func() {
			_, _, err := u.CalculateStateTreeOutput(crypto.SHA256)
			require.Error(t, err)
		})
		u = &UnitStateProof{UnitTreeCert: &UnitTreeCert{Path: []*mt.PathItem{nil}}, StateTreeCert: &StateTreeCert{}}
		require.NotPanics(t, func() {
			_, _, err := u.CalculateStateTreeOutput(crypto.SHA256)
			require.Error(t, err)
		})
	})
}
