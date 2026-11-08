package types

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	abcrypto "github.com/unicitynetwork/bft-go-base/crypto"
	abhex "github.com/unicitynetwork/bft-go-base/types/hex"
)

// The maximum-size fixture: epoch 1 is a genesis of 256 members with 128-byte node ids, epoch 2 has the same 256 members and carries a signature of every
// predecessor member, the largest valid entry the format admits (maximum weights, both optional hashes present). It is generated once
// (MAXENTRY_UPDATE=1 go test ./types -run TestMaxEntryFixture) and shared byte for byte with the SDKs and the aggregator. Signing is deterministic
// (RFC 6979), so the test also checks that the committed file is what the builder makes.
const maxEntryFile = "../testdata/trust-base-v2/max-entry/v1/max-entry.json"

type maxEntryFixture struct {
	Spec        []string `json:"spec"`
	Network     uint32   `json:"network"`
	Members     int      `json:"members"`
	NodeIDBytes int      `json:"nodeIdBytes"`
	Genesis     string   `json:"genesis"`   // hex, tag 39000, epoch 1
	GenesisID   string   `json:"genesisId"` // hex EntryID: the pin
	Entry       string   `json:"entry"`     // hex, tag 39000, epoch 2: the largest valid entry
	EntryID     string   `json:"entryId"`
	EntryBytes  int      `json:"entryBytes"`
	Bundle      string   `json:"bundle"` // hex, the two-entry release bundle (tag 39015)
}

func maxEntryChain(t *testing.T) (*RootTrustBaseV2, *RootTrustBaseV2) {
	var members []*NodeInfo
	var signers []abcrypto.Signer
	for i := 1; i <= MaxTrustBaseV2Members; i++ {
		s, err := abcrypto.NewInMemorySecp256K1SignerFromKey(append(make([]byte, 30), byte(i>>8), byte(i)))
		require.NoError(t, err)
		v, err := s.Verifier()
		require.NoError(t, err)
		pk, err := v.MarshalPublicKey()
		require.NoError(t, err)
		members = append(members, &NodeInfo{NodeID: fmt.Sprintf("%0*d", MaxTrustBaseV2NodeIDLen, i), SigKey: pk, Stake: MaxTrustBaseV2Weight})
		signers = append(signers, s)
	}
	threshold := (uint64(len(members))*MaxTrustBaseV2Weight*2)/3 + 1
	hash := func(b byte) abhex.Bytes {
		h := make([]byte, TrustBaseV2IDLen)
		for i := range h {
			h[i] = b
		}
		return h
	}
	g := &RootTrustBaseV2{Version: 2, NetworkID: 5, Epoch: 1, EpochStart: 1, RootNodes: members, QuorumThreshold: threshold, StateHash: hash(0x11),
		ChangeRecordHash: hash(0x22), PreviousEntryID: make([]byte, TrustBaseV2IDLen)}
	gid, err := g.EntryID()
	require.NoError(t, err)
	e := &RootTrustBaseV2{Version: 2, NetworkID: 5, Epoch: 2, EpochStart: 1 << 40, RootNodes: members, QuorumThreshold: threshold, StateHash: hash(0x33),
		ChangeRecordHash: hash(0x44), PreviousEntryID: gid[:]}
	for i, m := range members {
		require.NoError(t, e.Sign(m.NodeID, signers[i]))
	}
	return g, e
}

func buildMaxEntryFixture(t *testing.T) maxEntryFixture {
	g, e := maxEntryChain(t)
	gb, err := g.MarshalCBOR()
	require.NoError(t, err)
	eb, err := e.MarshalCBOR()
	require.NoError(t, err)
	gid, _ := g.EntryID()
	eid, _ := e.EntryID()
	bundle, err := EncodeTrustBaseBundle([][]byte{gb, eb})
	require.NoError(t, err)
	return maxEntryFixture{
		Spec: []string{
			"Epoch 1 is a genesis of 256 members with 128-byte node ids (decimal, zero padded), keys of the secp256k1 private keys 1..256 (32-byte big endian), every weight 2^40, both optional hashes present.",
			"Epoch 2 (start round 2^40) has the same members and carries the signature of every one of the 256 predecessor members over its unsigned bytes: the largest valid entry. `entryBytes` is its encoded length.",
			"`bundle` is the two-entry release bundle (tag 39015) of the pair; the genesis EntryID is the pin. MaxTrustBaseEntryBytes (128 KiB) must accept `entry`.",
		},
		Network: 5, Members: MaxTrustBaseV2Members, NodeIDBytes: MaxTrustBaseV2NodeIDLen,
		Genesis: hex.EncodeToString(gb), GenesisID: hex.EncodeToString(gid[:]), Entry: hex.EncodeToString(eb), EntryID: hex.EncodeToString(eid[:]),
		EntryBytes: len(eb), Bundle: hex.EncodeToString(bundle),
	}
}

func TestMaxEntryFixture(t *testing.T) {
	built := buildMaxEntryFixture(t)
	if os.Getenv("MAXENTRY_UPDATE") == "1" {
		out, err := json.MarshalIndent(built, "", "  ")
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(maxEntryFile, append(out, '\n'), 0o644))
	}
	data, err := os.ReadFile(maxEntryFile)
	require.NoError(t, err)
	var f maxEntryFixture
	require.NoError(t, json.Unmarshal(data, &f))
	require.Equal(t, built, f, "the committed fixture is not what the builder makes")

	eb, err := hex.DecodeString(f.Entry)
	require.NoError(t, err)
	gb, err := hex.DecodeString(f.Genesis)
	require.NoError(t, err)
	require.Equal(t, f.EntryBytes, len(eb))
	// the largest valid entry is well inside the cap, and the cap is not tight to it
	require.Greater(t, len(eb), 90_000)
	require.Less(t, len(eb), 100_000)
	require.Greater(t, MaxTrustBaseEntryBytes, len(eb)*5/4)

	g, err := DecodeRootTrustBaseV2(gb)
	require.NoError(t, err)
	e, err := DecodeRootTrustBaseV2(eb)
	require.NoError(t, err)
	require.Len(t, e.RootNodes, 256)
	require.Len(t, e.Signatures, 256)
	require.NoError(t, g.VerifyGenesis())
	require.NoError(t, e.VerifySuccessor(g))
	again, err := e.MarshalCBOR()
	require.NoError(t, err)
	require.Equal(t, eb, again, "round trip")

	// as a bundle and as a page of the response codec
	bundle, err := hex.DecodeString(f.Bundle)
	require.NoError(t, err)
	b, err := DecodeTrustBaseBundle(bundle, TrustBaseLimits{MaxBytes: len(bundle), MaxEntries: 2})
	require.NoError(t, err)
	pin, err := hex.DecodeString(f.GenesisID)
	require.NoError(t, err)
	var pinArr [TrustBaseV2IDLen]byte
	copy(pinArr[:], pin)
	require.NoError(t, VerifyTrustBaseBundle(b, pinArr))
	_, entries, err := DecodeTrustBaseResponse(bundle, TrustBasePageLimits)
	require.NoError(t, err, "two maximum-size entries fit one page")
	require.Len(t, entries, 2)

	// an entry beyond the cap is refused by the page decode
	over := &TrustBaseResponse{Version: 1, Network: 5, Status: TrustBaseStatusOK, FromEpoch: 1, EffectiveEnd: 1, EndEntryID: pin, Entries: nil}
	junk, err := Cbor.Marshal(make([]byte, MaxTrustBaseEntryBytes)) // a well-formed CBOR item longer than the cap
	require.NoError(t, err)
	over.Entries = append(over.Entries, junk)
	ob, err := over.Encode()
	require.NoError(t, err)
	_, _, err = DecodeTrustBaseResponse(ob, TrustBaseLimits{MaxBytes: len(ob), MaxEntries: 4})
	require.ErrorIs(t, err, ErrTrustBaseResponse)
	require.Contains(t, err.Error(), "entry of")
}
