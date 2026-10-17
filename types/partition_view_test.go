package types

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	testsig "github.com/unicitynetwork/bft-go-base/testutils/sig"
)

const pvTestPartition PartitionID = 0x0a0b0c0d

func pvHash(label string) []byte {
	h := sha256.Sum256([]byte(label))
	return h[:]
}

// pvScheme returns scheme with 2^bits equal prefix shards (empty for bits==0).
func pvScheme(bits int) ShardingScheme {
	if bits == 0 {
		return ShardingScheme{}
	}
	ids := []ShardID{{}}
	for ; bits > 0; bits-- {
		var next []ShardID
		for _, id := range ids {
			a, b := id.Split()
			next = append(next, a, b)
		}
		ids = next
	}
	return ShardingScheme(ids)
}

func pvTopology(scheme ShardingScheme) PartitionViewTopology {
	topo := PartitionViewTopology{Scheme: scheme, ShardConfHashes: map[string][]byte{}}
	for id := range scheme.All() {
		topo.ShardConfHashes[id.Key()] = pvHash("conf-" + id.String())
	}
	return topo
}

// deterministic view for the scheme, leaves in canonical order
func pvView(t testing.TB, scheme ShardingScheme) *PartitionViewV1 {
	order, err := CanonicalShardOrder(scheme)
	require.NoError(t, err)
	v := &PartitionViewV1{Version: 1, PartitionID: pvTestPartition}
	for i, id := range order {
		ir := &InputRecord{
			Version:         1,
			RoundNumber:     uint64(100 + i),
			Epoch:           uint64(i % 2),
			PreviousHash:    pvHash("prev-" + id.String()),
			Hash:            pvHash("state-" + id.String()),
			SummaryValue:    []byte{},
			Timestamp:       1731504540 + uint64(i),
			BlockHash:       pvHash("block-" + id.String()),
			SumOfEarnedFees: 1<<53 + uint64(i), // above JS safe integer
		}
		if i == 1 { // unchanged state: nil block hash, nil ETHash
			ir.PreviousHash, ir.BlockHash = ir.Hash, nil
		}
		v.Leaves = append(v.Leaves, PartitionViewLeafV1{
			ShardID:       id,
			InputRecord:   ir,
			TRHash:        pvHash("tr-" + id.String()),
			ShardConfHash: pvHash("conf-" + id.String()),
		})
	}
	return v
}

type pvFixture struct {
	view     *PartitionViewV1
	topo     PartitionViewTopology
	tree     ShardTree
	uc       *UnicityCertificate // enclosing UC of the first shard
	tb       RootTrustBase
	sealOnly *UnicitySeal
}

// pvEnclose builds a two partition unicity tree and signs the seal.
func pvEnclose(t *testing.T, view *PartitionViewV1, topo PartitionViewTopology) *pvFixture {
	tree, err := CreateShardTree(topo.Scheme, view.treeInputs(), crypto.SHA256)
	require.NoError(t, err)
	ut, err := NewUnicityTree(crypto.SHA256, []*UnicityTreeData{
		{Partition: pvTestPartition, ShardTreeRoot: tree.RootHash()},
		{Partition: 0x01010101, ShardTreeRoot: pvHash("other partition")},
	})
	require.NoError(t, err)
	utc, err := ut.Certificate(pvTestPartition)
	require.NoError(t, err)
	require.NotEmpty(t, utc.HashSteps)

	signer, verifier := testsig.CreateSignerAndVerifier(t)
	tb := NewTrustBaseT(t, verifier)
	seal := &UnicitySeal{Version: 1, NetworkID: tb.GetNetworkID(), Epoch: tb.GetEpoch(), RootChainRoundNumber: tb.GetEpochStart() + 77, Timestamp: NewTimestamp(), PreviousHash: pvHash("prev root"), Hash: ut.RootHash()}
	require.NoError(t, seal.Sign("test", signer))

	l := view.Leaves[0]
	stc, err := tree.Certificate(l.ShardID)
	require.NoError(t, err)
	return &pvFixture{
		view: view, topo: topo, tree: tree, tb: tb, sealOnly: seal,
		uc: &UnicityCertificate{
			Version: 1, InputRecord: l.InputRecord, TRHash: l.TRHash, ShardConfHash: l.ShardConfHash,
			ShardTreeCertificate: stc, UnicityTreeCertificate: utc, UnicitySeal: seal,
		},
	}
}

func Test_PartitionView_Golden(t *testing.T) {
	// minimal view, the exact bytes are part of the frozen contract
	ir := &InputRecord{Version: 1, PreviousHash: []byte{}, Hash: []byte{}}
	v := &PartitionViewV1{Version: 1, PartitionID: 1, Leaves: []PartitionViewLeafV1{{
		InputRecord: ir, TRHash: bytes.Repeat([]byte{1}, 32), ShardConfHash: bytes.Repeat([]byte{2}, 32),
	}}}
	data, err := v.MarshalCBOR()
	require.NoError(t, err)
	// [1, 1, [[h'80', #39002([1,0,0,h'',h'',null,0,null,0,null]), h'01..', h'02..']]]
	exp := "83" + "01" + "01" + "81" + "84" +
		"4180" +
		"d9985a" + "8a" + "01" + "00" + "00" + "40" + "40" + "f6" + "00" + "f6" + "00" + "f6" +
		"5820" + strings.Repeat("01", 32) +
		"5820" + strings.Repeat("02", 32)
	require.Equal(t, exp, hex.EncodeToString(data))

	dec, err := DecodePartitionViewV1(data)
	require.NoError(t, err)
	require.Equal(t, v, dec)
}

func Test_PartitionView_RoundTrip(t *testing.T) {
	for _, bits := range []int{0, 1, 2, 3} {
		t.Run(fmt.Sprintf("%d shards", 1<<bits), func(t *testing.T) {
			v := pvView(t, pvScheme(bits))
			data, err := v.MarshalCBOR()
			require.NoError(t, err)
			require.Less(t, len(data), MaxPartitionViewBytes)
			dec, err := DecodePartitionViewV1(data)
			require.NoError(t, err)
			require.Equal(t, v, dec)
			// the pointer receiver encoding is the same
			data2, err := Cbor.Marshal(dec)
			require.NoError(t, err)
			require.Equal(t, data, data2)
		})
	}
}

func Test_PartitionView_NilVersusEmpty(t *testing.T) {
	v := pvView(t, pvScheme(1))
	ir := v.Leaves[0].InputRecord
	ir.ETHash, ir.BlockHash = nil, []byte{}
	ir.PreviousHash, ir.Hash = []byte{}, []byte{}
	data, err := v.MarshalCBOR()
	require.NoError(t, err)
	dec, err := DecodePartitionViewV1(data)
	require.NoError(t, err)
	got := dec.Leaves[0].InputRecord
	require.Nil(t, got.ETHash)
	require.NotNil(t, got.BlockHash)
	require.Empty(t, got.BlockHash)
	require.NotNil(t, got.Hash)
	// and the same view with the distinction removed encodes differently
	ir.ETHash, ir.BlockHash = []byte{}, nil
	data2, err := v.MarshalCBOR()
	require.NoError(t, err)
	require.NotEqual(t, data, data2)
}

func Test_PartitionView_StrictDecode(t *testing.T) {
	v := pvView(t, pvScheme(1))
	good, err := v.MarshalCBOR()
	require.NoError(t, err)

	t.Run("trailing bytes", func(t *testing.T) {
		_, err := DecodePartitionViewV1(append(bytes.Clone(good), 0))
		require.Error(t, err)
	})
	t.Run("truncated", func(t *testing.T) {
		_, err := DecodePartitionViewV1(good[:len(good)-1])
		require.Error(t, err)
	})
	t.Run("empty and null", func(t *testing.T) {
		for _, b := range [][]byte{nil, {}, {0xf6}, {0x80}} {
			_, err := DecodePartitionViewV1(b)
			require.Error(t, err)
		}
	})
	t.Run("version zero is not defaulted", func(t *testing.T) {
		b := bytes.Clone(good)
		require.EqualValues(t, 0x83, b[0])
		b[1] = 0
		_, err := DecodePartitionViewV1(b)
		require.ErrorContains(t, err, "unsupported partition view version 0")
	})
	t.Run("unknown version", func(t *testing.T) {
		b := bytes.Clone(good)
		b[1] = 2
		_, err := DecodePartitionViewV1(b)
		require.ErrorContains(t, err, "unsupported partition view version 2")
	})
	t.Run("marshal refuses version zero", func(t *testing.T) {
		bad := v.Clone()
		bad.Version = 0
		_, err := bad.MarshalCBOR()
		require.ErrorContains(t, err, "version")
	})
	t.Run("extra array item", func(t *testing.T) {
		b := append([]byte{0x84}, good[1:]...)
		b = append(b, 0x00)
		_, err := DecodePartitionViewV1(b)
		require.Error(t, err)
	})
	t.Run("indefinite length array", func(t *testing.T) {
		// 9f 01 01 <leaves array> ff
		b := append([]byte{0x9f}, good[1:]...)
		b = append(b, 0xff)
		_, err := DecodePartitionViewV1(b)
		require.Error(t, err)
	})
	t.Run("non canonical integer", func(t *testing.T) {
		// version 1 encoded in two bytes
		b := append([]byte{0x83, 0x18, 0x01}, good[2:]...)
		_, err := DecodePartitionViewV1(b)
		require.ErrorContains(t, err, "canonical")
	})
	t.Run("shard id is a bstr not a number", func(t *testing.T) {
		b := bytes.Clone(good)
		// first leaf: 0x84 (array4) 0x41 0x.. (bstr 1) -> replace with unsigned int
		i := bytes.Index(b, []byte{0x84, 0x41})
		require.Positive(t, i)
		b = append(b[:i+1], append([]byte{0x01}, b[i+3:]...)...)
		_, err := DecodePartitionViewV1(b)
		require.Error(t, err)
	})
	t.Run("malformed end marker", func(t *testing.T) {
		b := bytes.Clone(good)
		i := bytes.Index(b, []byte{0x84, 0x41})
		b[i+2] = 0x00 // no end marker bit
		_, err := DecodePartitionViewV1(b)
		require.Error(t, err)
	})
	t.Run("oversize", func(t *testing.T) {
		_, err := DecodePartitionViewV1(make([]byte, MaxPartitionViewBytes+1))
		require.ErrorContains(t, err, "limit")
	})
	t.Run("huge declared array does not allocate", func(t *testing.T) {
		// array of 2^32 items claimed in 9 bytes
		_, err := DecodePartitionViewV1([]byte{0x83, 0x01, 0x01, 0x9b, 0, 0, 0, 1, 0, 0, 0, 0})
		require.Error(t, err)
	})
	t.Run("untagged", func(t *testing.T) {
		b := append([]byte{0xd9, 0x9a, 0x5a}, good...) // some tag
		_, err := DecodePartitionViewV1(b)
		require.Error(t, err)
	})
}

func Test_PartitionView_Bounds(t *testing.T) {
	enc := func(mod func(v *PartitionViewV1)) error {
		v := pvView(t, pvScheme(1))
		mod(v)
		_, err := v.MarshalCBOR()
		return err
	}
	require.NoError(t, enc(func(v *PartitionViewV1) {}))
	require.ErrorContains(t, enc(func(v *PartitionViewV1) { v.PartitionID = 0 }), "partition ID")
	require.ErrorContains(t, enc(func(v *PartitionViewV1) { v.Leaves = nil }), "leaf count")
	require.ErrorContains(t, enc(func(v *PartitionViewV1) {
		for len(v.Leaves) < MaxPartitionViewLeaves+1 {
			v.Leaves = append(v.Leaves, v.Leaves[0])
		}
	}), "leaf count")
	require.ErrorContains(t, enc(func(v *PartitionViewV1) { v.Leaves[0].InputRecord = nil }), "input record")
	require.ErrorContains(t, enc(func(v *PartitionViewV1) { v.Leaves[0].TRHash = v.Leaves[0].TRHash[:31] }), "TRHash")
	require.ErrorContains(t, enc(func(v *PartitionViewV1) { v.Leaves[0].TRHash = nil }), "TRHash")
	require.ErrorContains(t, enc(func(v *PartitionViewV1) { v.Leaves[0].ShardConfHash = make([]byte, 33) }), "ShardConfHash")
	require.ErrorContains(t, enc(func(v *PartitionViewV1) { v.Leaves[0].InputRecord.Hash = []byte{1} }), "state hash")
	require.ErrorContains(t, enc(func(v *PartitionViewV1) { v.Leaves[0].InputRecord.ETHash = make([]byte, 31) }), "executed transactions hash")
	require.ErrorContains(t, enc(func(v *PartitionViewV1) {
		v.Leaves[0].InputRecord.SummaryValue = make([]byte, MaxPartitionViewSummaryValueBytes+1)
	}), "summary value")
	require.NoError(t, enc(func(v *PartitionViewV1) {
		v.Leaves[0].InputRecord.SummaryValue = make([]byte, MaxPartitionViewSummaryValueBytes)
	}))
	require.ErrorContains(t, enc(func(v *PartitionViewV1) { v.Leaves[0].ShardID.length = MaxPartitionViewShardIDBits + 1 }), "bits")
	require.ErrorContains(t, enc(func(v *PartitionViewV1) { v.Leaves[0].InputRecord.Version = 2 }), "version")
}

func Test_CanonicalShardOrder(t *testing.T) {
	ids := func(s ShardingScheme) (r []string) {
		o, err := CanonicalShardOrder(s)
		require.NoError(t, err)
		for _, id := range o {
			r = append(r, id.String())
		}
		return r
	}
	require.Equal(t, []string{""}, ids(ShardingScheme{}))
	s4 := pvScheme(2)
	// scrambled input order must not matter
	scrambled := ShardingScheme{s4[3], s4[0], s4[2], s4[1]}
	require.Equal(t, []string{"00", "01", "10", "11"}, ids(scrambled))
	require.Equal(t, []string{"000", "001", "010", "011", "100", "101", "110", "111"}, ids(pvScheme(3)))
	// uneven but complete scheme
	a, b := ShardID{}.Split()
	b0, b1 := b.Split()
	require.Equal(t, []string{"0", "10", "11"}, ids(ShardingScheme{b1, a, b0}))

	// singleton ID is the empty bitstring, native bstr 80
	d, err := ShardID{}.MarshalCBOR()
	require.NoError(t, err)
	require.Equal(t, []byte{0x41, 0x80}, d)

	t.Run("incomplete", func(t *testing.T) {
		_, err := CanonicalShardOrder(ShardingScheme{a, b0})
		require.ErrorContains(t, err, "cover")
		_, err = CanonicalShardOrder(ShardingScheme{s4[0], s4[1], s4[2]})
		require.ErrorContains(t, err, "cover")
	})
	t.Run("overlapping", func(t *testing.T) {
		_, err := CanonicalShardOrder(ShardingScheme{a, b, b0})
		require.ErrorContains(t, err, "prefix")
	})
	t.Run("single item scheme", func(t *testing.T) {
		_, err := CanonicalShardOrder(ShardingScheme{ShardID{}})
		require.Error(t, err)
	})
	t.Run("too many shards", func(t *testing.T) {
		_, err := CanonicalShardOrder(pvScheme(4))
		require.ErrorContains(t, err, "limit")
	})
}

func Test_PartitionView_ValidateStructure(t *testing.T) {
	scheme := pvScheme(2)
	topo := pvTopology(scheme)
	good := pvView(t, scheme)
	require.NoError(t, good.ValidateStructure(pvTestPartition, topo))

	cases := map[string]struct {
		mod func(v *PartitionViewV1)
		err string
	}{
		"wrong partition": {func(v *PartitionViewV1) { v.PartitionID++ }, "expected"},
		"missing":         {func(v *PartitionViewV1) { v.Leaves = v.Leaves[:3] }, "3 leaves"},
		"extra":           {func(v *PartitionViewV1) { v.Leaves = append(v.Leaves, v.Leaves[0]) }, "5 leaves"},
		"duplicate":       {func(v *PartitionViewV1) { v.Leaves[1] = v.Leaves[0] }, "expected"},
		"reordered":       {func(v *PartitionViewV1) { v.Leaves[0], v.Leaves[1] = v.Leaves[1], v.Leaves[0] }, "expected"},
		"wrong shard":     {func(v *PartitionViewV1) { v.Leaves[3].ShardID = ShardID{bits: []byte{0x80}, length: 1} }, "expected"},
		"conf hash":       {func(v *PartitionViewV1) { v.Leaves[2].ShardConfHash = pvHash("other config") }, "configuration hash"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			v := good.Clone()
			tc.mod(v)
			require.ErrorContains(t, v.ValidateStructure(pvTestPartition, topo), tc.err)
		})
	}
	t.Run("view of another topology", func(t *testing.T) {
		require.ErrorContains(t, good.ValidateStructure(pvTestPartition, pvTopology(pvScheme(3))), "4 leaves")
		require.ErrorContains(t, good.ValidateStructure(pvTestPartition, pvTopology(ShardingScheme{})), "1 shards")
	})
	t.Run("nil", func(t *testing.T) {
		var v *PartitionViewV1
		require.Error(t, v.ValidateStructure(pvTestPartition, topo))
	})
}

func Test_PartitionView_ClonesAreDeep(t *testing.T) {
	v := pvView(t, pvScheme(1))
	c := v.Clone()
	require.Equal(t, v, c)
	c.Leaves[0].TRHash[0] ^= 0xff
	c.Leaves[0].InputRecord.Hash[0] ^= 0xff
	c.Leaves[0].ShardID.bits = append(c.Leaves[0].ShardID.bits[:0], 0xff)
	require.NotEqual(t, v.Leaves[0].TRHash, c.Leaves[0].TRHash)
	require.NotEqual(t, v.Leaves[0].InputRecord.Hash, c.Leaves[0].InputRecord.Hash)
	require.Equal(t, pvView(t, pvScheme(1)), v)
}

func Test_PartitionView_NativeTreeEquivalence(t *testing.T) {
	for _, bits := range []int{0, 1, 2, 3} {
		t.Run(fmt.Sprintf("%d shards", 1<<bits), func(t *testing.T) {
			scheme := pvScheme(bits)
			topo := pvTopology(scheme)
			view := pvView(t, scheme)
			f := pvEnclose(t, view, topo)

			// view -> tree equals the tree built by the producer from the same inputs (any order)
			tree, err := view.BuildShardTree(pvTestPartition, topo, crypto.SHA256)
			require.NoError(t, err)
			require.Equal(t, f.tree, tree)

			// and survives the wire
			data, err := view.MarshalCBOR()
			require.NoError(t, err)
			dec, err := DecodePartitionViewV1(data)
			require.NoError(t, err)

			ucs, err := dec.AssembleCertificates(f.uc, pvTestPartition, topo, TrustBaseSealVerifier(f.tb), crypto.SHA256)
			require.NoError(t, err)
			require.Len(t, ucs, len(view.Leaves))

			sealBytes, err := f.uc.UnicitySeal.MarshalCBOR()
			require.NoError(t, err)
			for i, uc := range ucs {
				l := view.Leaves[i]
				// natively verifiable ordinary UC for every shard
				require.NoError(t, uc.Verify(f.tb, crypto.SHA256, pvTestPartition, l.ShardID, l.ShardConfHash), l.ShardID.String())
				cert, err := f.tree.Certificate(l.ShardID)
				require.NoError(t, err)
				require.Equal(t, cert, uc.ShardTreeCertificate)
				sb, err := uc.UnicitySeal.MarshalCBOR()
				require.NoError(t, err)
				require.Equal(t, sealBytes, sb, "identical seal encoding")
				require.NotSame(t, f.uc.UnicitySeal, uc.UnicitySeal)
				require.Equal(t, f.uc.UnicityTreeCertificate, uc.UnicityTreeCertificate)
			}
			// the shard of the enclosing UC is reproduced byte for byte
			want, err := f.uc.MarshalCBOR()
			require.NoError(t, err)
			got, err := ucs[0].MarshalCBOR()
			require.NoError(t, err)
			require.Equal(t, want, got)
			// derived UCs do not alias the view
			ucs[0].InputRecord.Hash[0] ^= 0xff
			require.NotEqual(t, ucs[0].InputRecord.Hash, view.Leaves[0].InputRecord.Hash)
		})
	}
}

func Test_PartitionView_VerifyTreeNegative(t *testing.T) {
	scheme := pvScheme(2)
	topo := pvTopology(scheme)
	f := pvEnclose(t, pvView(t, scheme), topo)
	verify := func(view *PartitionViewV1, uc *UnicityCertificate) error {
		_, err := view.AssembleCertificates(uc, pvTestPartition, topo, TrustBaseSealVerifier(f.tb), crypto.SHA256)
		return err
	}
	require.NoError(t, verify(f.view, f.uc))

	t.Run("flip every committed field", func(t *testing.T) {
		flips := map[string]func(l *PartitionViewLeafV1){
			"round":        func(l *PartitionViewLeafV1) { l.InputRecord.RoundNumber++ },
			"epoch":        func(l *PartitionViewLeafV1) { l.InputRecord.Epoch++ },
			"previousHash": func(l *PartitionViewLeafV1) { l.InputRecord.PreviousHash[0] ^= 1 },
			"hash":         func(l *PartitionViewLeafV1) { l.InputRecord.Hash[0] ^= 1 },
			"summary":      func(l *PartitionViewLeafV1) { l.InputRecord.SummaryValue = []byte{1} },
			"timestamp":    func(l *PartitionViewLeafV1) { l.InputRecord.Timestamp++ },
			"blockHash":    func(l *PartitionViewLeafV1) { l.InputRecord.BlockHash = pvHash("bh") },
			"fees":         func(l *PartitionViewLeafV1) { l.InputRecord.SumOfEarnedFees++ },
			"ETHash":       func(l *PartitionViewLeafV1) { l.InputRecord.ETHash = pvHash("et") },
			"trHash":       func(l *PartitionViewLeafV1) { l.TRHash[0] ^= 1 },
		}
		for name, flip := range flips {
			for i := range f.view.Leaves {
				v := f.view.Clone()
				flip(&v.Leaves[i])
				require.Error(t, verify(v, f.uc), "%s of leaf %d", name, i)
			}
		}
		// config hash is bound to the trusted topology first
		v := f.view.Clone()
		v.Leaves[1].ShardConfHash[0] ^= 1
		require.ErrorContains(t, verify(v, f.uc), "configuration hash")
	})
	t.Run("sibling hash of the partition path", func(t *testing.T) {
		uc := *f.uc
		utc := *uc.UnicityTreeCertificate
		utc.HashSteps = []*PathItem{{Key: utc.HashSteps[0].Key, Hash: pvHash("x")}}
		uc.UnicityTreeCertificate = &utc
		require.ErrorContains(t, verify(f.view, &uc), "does not match the seal")
	})
	t.Run("partition certificate of another view", func(t *testing.T) {
		uc := *f.uc
		uc.UnicityTreeCertificate = &UnicityTreeCertificate{Version: 1, Partition: 0x01010101, HashSteps: f.uc.UnicityTreeCertificate.HashSteps}
		require.ErrorContains(t, verify(f.view, &uc), "partition")
	})
	t.Run("seal field", func(t *testing.T) {
		for name, mod := range map[string]func(s *UnicitySeal){
			"hash":      func(s *UnicitySeal) { s.Hash = pvHash("h") },
			"round":     func(s *UnicitySeal) { s.RootChainRoundNumber++ },
			"network":   func(s *UnicitySeal) { s.NetworkID++ },
			"epoch":     func(s *UnicitySeal) { s.Epoch++ },
			"timestamp": func(s *UnicitySeal) { s.Timestamp++ },
			"previous":  func(s *UnicitySeal) { s.PreviousHash = pvHash("p") },
			"signature": func(s *UnicitySeal) {
				for k := range s.Signatures {
					s.Signatures[k] = append([]byte{0}, s.Signatures[k][1:]...)
				}
			},
			"no signatures": func(s *UnicitySeal) { s.Signatures = nil },
		} {
			uc := *f.uc
			s := *f.uc.UnicitySeal
			s.Signatures = SignatureMap{}
			for k, v := range f.uc.UnicitySeal.Signatures {
				s.Signatures[k] = bytes.Clone(v)
			}
			mod(&s)
			uc.UnicitySeal = &s
			require.Error(t, verify(f.view, &uc), name)
		}
	})
	t.Run("wrong trust base", func(t *testing.T) {
		_, verifier := testsig.CreateSignerAndVerifier(t)
		_, err := f.view.AssembleCertificates(f.uc, pvTestPartition, topo, TrustBaseSealVerifier(NewTrustBaseT(t, verifier)), crypto.SHA256)
		require.ErrorContains(t, err, "authenticating unicity seal")
	})
	t.Run("nil verifier and nil UC parts", func(t *testing.T) {
		_, err := f.view.AssembleCertificates(f.uc, pvTestPartition, topo, nil, crypto.SHA256)
		require.ErrorIs(t, err, ErrRootValidatorInfoMissing)
		require.Error(t, verify(f.view, nil))
		uc := *f.uc
		uc.UnicityTreeCertificate = nil
		require.Error(t, verify(f.view, &uc))
		uc = *f.uc
		uc.UnicitySeal = nil
		require.Error(t, verify(f.view, &uc))
	})
	t.Run("enclosing UC leaf mismatch", func(t *testing.T) {
		uc := *f.uc
		ir := *uc.InputRecord
		ir.Timestamp++
		uc.InputRecord = &ir
		require.Error(t, verify(f.view, &uc))
		uc = *f.uc
		uc.TRHash = pvHash("tr")
		require.Error(t, verify(f.view, &uc))
		uc = *f.uc
		uc.ShardTreeCertificate.Shard = ShardID{bits: []byte{0x80}, length: 1}
		require.Error(t, verify(f.view, &uc))
	})
	t.Run("shard certificate path", func(t *testing.T) {
		uc := *f.uc
		stc := f.uc.ShardTreeCertificate
		stc.SiblingHashes = [][]byte{pvHash("a"), pvHash("b")}
		uc.ShardTreeCertificate = stc
		require.Error(t, verify(f.view, &uc))
	})
	t.Run("assembly needs admitted config hashes of all shards", func(t *testing.T) {
		partial := PartitionViewTopology{Scheme: scheme, ShardConfHashes: map[string][]byte{}}
		_, err := f.view.AssembleCertificates(f.uc, pvTestPartition, partial, TrustBaseSealVerifier(f.tb), crypto.SHA256)
		require.ErrorContains(t, err, "admitted configuration hash is required")
		// structure validation alone does not need them
		_, err = f.view.VerifyTree(f.uc, pvTestPartition, partial, crypto.SHA256)
		require.NoError(t, err)
	})
	t.Run("the input view is not modified", func(t *testing.T) {
		before, err := f.view.MarshalCBOR()
		require.NoError(t, err)
		_, err = f.view.AssembleCertificates(f.uc, pvTestPartition, topo, TrustBaseSealVerifier(f.tb), crypto.SHA256)
		require.NoError(t, err)
		after, err := f.view.MarshalCBOR()
		require.NoError(t, err)
		require.Equal(t, before, after)
	})
}

// codec vectors shared with other implementations, regenerate with
// PARTITION_VIEW_REGEN=1 go test ./types -run Test_PartitionView_Vectors
type pvManifest struct {
	Version   int               `json:"version"`
	Partition uint32            `json:"partitionId"`
	Files     map[string]string `json:"sha256"`
}

func Test_PartitionView_Vectors(t *testing.T) {
	dir := filepath.Join("testdata", "partition-view", "v1")
	regen := os.Getenv("PARTITION_VIEW_REGEN") != ""
	want := map[string][]byte{}
	for name, bits := range map[string]int{"shards-1": 0, "shards-4": 2, "shards-8": 3} {
		data, err := pvView(t, pvScheme(bits)).MarshalCBOR()
		require.NoError(t, err)
		want[name+".cbor"] = data
	}
	if regen {
		require.NoError(t, os.MkdirAll(dir, 0o755))
		man := pvManifest{Version: 1, Partition: uint32(pvTestPartition), Files: map[string]string{}}
		for name, data := range want {
			require.NoError(t, os.WriteFile(filepath.Join(dir, name), data, 0o644))
			sum := sha256.Sum256(data)
			man.Files[name] = hex.EncodeToString(sum[:])
		}
		b, err := json.MarshalIndent(man, "", "  ")
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(filepath.Join(dir, "manifest.json"), append(b, '\n'), 0o644))
	}

	b, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
	require.NoError(t, err)
	var man pvManifest
	require.NoError(t, json.Unmarshal(b, &man))
	require.Len(t, man.Files, len(want))
	for name, data := range want {
		got, err := os.ReadFile(filepath.Join(dir, name))
		require.NoError(t, err)
		sum := sha256.Sum256(got)
		require.Equal(t, man.Files[name], hex.EncodeToString(sum[:]), name)
		require.Equal(t, data, got, "%s differs from generated, regenerate deliberately", name)
		_, err = DecodePartitionViewV1(got)
		require.NoError(t, err, name)
	}
}

func Test_TrustBaseSealVerifier_AuthorityContext(t *testing.T) {
	signer, verifier := testsig.CreateSignerAndVerifier(t)
	sigKey, err := verifier.MarshalPublicKey()
	require.NoError(t, err)
	newTB := func(net NetworkID, epoch, start uint64) RootTrustBase {
		tb, err := NewTrustBase(net, []*NodeInfo{{NodeID: "test", SigKey: sigKey, Stake: 1}}, WithEpoch(epoch), WithEpochStart(start))
		require.NoError(t, err)
		return tb
	}
	// the same keys are trusted in all of these contexts
	tb := newTB(NetworkMainNet, 3, 50)
	sign := func(net NetworkID, epoch, round uint64) *UnicitySeal {
		s := &UnicitySeal{Version: 1, NetworkID: net, Epoch: epoch, RootChainRoundNumber: round, Timestamp: NewTimestamp(), Hash: pvHash("root")}
		require.NoError(t, s.Sign("test", signer))
		return s
	}
	v := TrustBaseSealVerifier(tb)
	require.NoError(t, v.VerifySeal(sign(NetworkMainNet, 3, 50)))
	require.NoError(t, v.VerifySeal(sign(NetworkMainNet, 3, 51)))
	require.ErrorContains(t, v.VerifySeal(sign(NetworkMainNet+1, 3, 60)), "network")
	require.ErrorContains(t, v.VerifySeal(sign(NetworkMainNet, 2, 60)), "epoch")
	require.ErrorContains(t, v.VerifySeal(sign(NetworkMainNet, 4, 60)), "epoch")
	require.ErrorContains(t, v.VerifySeal(sign(NetworkMainNet, 3, 49)), "before the start")
	require.Error(t, v.VerifySeal(nil))
	require.Error(t, TrustBaseSealVerifier(nil).VerifySeal(sign(NetworkMainNet, 3, 60)))

	// and through assembly: validly signed seal of another network/epoch is refused
	scheme := pvScheme(1)
	topo := pvTopology(scheme)
	view := pvView(t, scheme)
	f := pvEnclose(t, view, topo)
	for name, tbx := range map[string]RootTrustBase{
		"network": newTB(NetworkMainNet+1, f.tb.GetEpoch(), 0),
		"epoch":   newTB(f.tb.GetNetworkID(), f.tb.GetEpoch()+1, 0),
	} {
		_, err := view.AssembleCertificates(f.uc, pvTestPartition, topo, TrustBaseSealVerifier(tbx), crypto.SHA256)
		require.Error(t, err, name)
	}
}

func Test_PartitionView_NilPathStep(t *testing.T) {
	scheme := pvScheme(2)
	topo := pvTopology(scheme)
	f := pvEnclose(t, pvView(t, scheme), topo)
	uc := *f.uc
	utc := *uc.UnicityTreeCertificate
	utc.HashSteps = []*PathItem{nil}
	uc.UnicityTreeCertificate = &utc
	// the nil entry survives native wire round trip
	b, err := uc.MarshalCBOR()
	require.NoError(t, err)
	var wire UnicityCertificate
	require.NoError(t, wire.UnmarshalCBOR(b))
	require.Len(t, wire.UnicityTreeCertificate.HashSteps, 1)
	require.Nil(t, wire.UnicityTreeCertificate.HashSteps[0])

	require.NotPanics(t, func() {
		_, err := f.view.VerifyTree(&wire, pvTestPartition, topo, crypto.SHA256)
		require.ErrorContains(t, err, "hash step 0 is nil")
		_, err = f.view.AssembleCertificates(&wire, pvTestPartition, topo, TrustBaseSealVerifier(f.tb), crypto.SHA256)
		require.ErrorContains(t, err, "hash step 0 is nil")
	})
}

// With several malformed hashes the first one in the fixed field order is reported, every time
// (bft-go-base#12: iterating a map literal reported a random one).
func TestPartitionViewLeaf_ValidateBounds_FirstMalformedHashIsReported(t *testing.T) {
	bad, bad2 := []byte{1, 2, 3, 4, 5}, []byte{6, 7, 8, 9, 10} // different, as an unchanged state has other rules
	leaf := func(mutate func(ir *InputRecord)) PartitionViewLeafV1 {
		l := pvView(t, ShardingScheme{}).Leaves[0]
		ir := *l.InputRecord
		l.InputRecord = &ir
		mutate(l.InputRecord)
		return l
	}
	tests := []struct {
		name   string
		mutate func(ir *InputRecord)
		want   string
	}{
		{"all malformed", func(ir *InputRecord) { ir.Hash, ir.PreviousHash, ir.BlockHash, ir.ETHash = bad, bad2, bad, bad }, "state hash must be empty or 32 bytes, got 5"},
		{"all but state hash", func(ir *InputRecord) { ir.PreviousHash, ir.BlockHash, ir.ETHash = bad2, bad, bad }, "previous hash must be empty or 32 bytes, got 5"},
		{"block and ET hash", func(ir *InputRecord) { ir.BlockHash, ir.ETHash = bad, bad }, "block hash must be empty or 32 bytes, got 5"},
		{"ET hash only", func(ir *InputRecord) { ir.ETHash = bad }, "executed transactions hash must be empty or 32 bytes, got 5"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			l := leaf(tc.mutate)
			for range 300 {
				require.EqualError(t, l.validateBounds(), tc.want)
			}
		})
	}
}
