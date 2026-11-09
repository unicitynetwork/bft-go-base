package types

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/require"
)

// Shared cross-language vectors for the Unicity Trust Base v2 (testdata/trust-base-v2/v1/vectors.json). SDKs in other languages consume the file; this test
// regenerates it (UPDATE_VECTORS=1) and otherwise checks that the committed file is exactly what the Go reference produces.
//
// The test keys are the repeated bytes 0x01.. 0x04 (members "a".."d" take key bytes 1..4); they sign nothing real. secp256k1 signing is deterministic (RFC 6979).
//
// History model ("append"), shared with the SDKs, applied to a held chain of entries (epochs 1..n):
//   - the first entry of an empty history must be a genesis entry (it is authenticated by an out-of-band pin on its entryId, not tested here);
//   - an entry of epoch <= n: if its entryId equals the held entry's, nothing changes ("noop", the new signature set must still verify, so a bad witness is an
//     error); a different entryId for a held epoch is "conflict";
//   - an entry of epoch > n+1 is "gap";
//   - epoch n+1 must pass VerifySuccessor(held tip): otherwise the error class of that check ("chain", "signature", "invalid").
const tbBundleTag = 39015

type tbVecEntry struct {
	Name     string `json:"name"`
	Hex      string `json:"hex"`
	EntryID  string `json:"entryId"`
	SigBytes string `json:"sigBytes"`
}

type tbVecDecode struct {
	Name  string `json:"name"`
	Hex   string `json:"hex"`
	Valid bool   `json:"valid"`
	Class string `json:"errorClass,omitempty"` // "encoding" | "invalid"
}

type tbVecBundle struct {
	Name     string   `json:"name"`
	Hex      string   `json:"hex"`
	EntryIDs []string `json:"entryIds"`
}

type tbVecStep struct {
	Entry   string `json:"entry"` // hex of the tagged entry
	Outcome string `json:"outcome"`
}

type tbVecHistory struct {
	Name  string      `json:"name"`
	Steps []tbVecStep `json:"steps"`
	Final []string    `json:"finalEntryIds"` // the held chain after all steps
}

type tbVecQuorum struct {
	Name      string   `json:"name"`
	Committee string   `json:"committee"` // entry name whose members verify
	Signers   []string `json:"signers"`
	Weight    uint64   `json:"signedWeight"`
	Threshold uint64   `json:"threshold"`
	Valid     bool     `json:"valid"`
	Entry     string   `json:"entry"`
}

type tbVectors struct {
	Spec     []string       `json:"spec"`
	Entries  []tbVecEntry   `json:"entries"`
	Decode   []tbVecDecode  `json:"decode"`
	Bundles  []tbVecBundle  `json:"bundles"`
	History  []tbVecHistory `json:"history"`
	Weighted []tbVecQuorum  `json:"weightedQuorum"`
}

func tbHex(b []byte) string { return hex.EncodeToString(b) }

func tbEncode(t *testing.T, e *RootTrustBaseV2) []byte {
	b, err := e.MarshalCBOR()
	require.NoError(t, err)
	return b
}

func tbID(t *testing.T, e *RootTrustBaseV2) string {
	id, err := e.EntryID()
	require.NoError(t, err)
	return tbHex(id[:])
}

// tbBundle is the complete release bundle, the tag-39015 GetTrustBase response with status OK as bft-core gettrustbase.EncodeBundle writes it:
// [version=1, network, status=0, fromEpoch, effectiveEnd, endEntryID, [entry, ...], null]. Every entry is a complete tag-39000 value, epochs ascending
// from the genesis entry; the cursor (last element) is null.
func tbBundle(t *testing.T, entries ...*RootTrustBaseV2) []byte {
	raws := make([]cbor.RawMessage, 0, len(entries))
	for _, e := range entries {
		raws = append(raws, tbEncode(t, e))
	}
	first, last := entries[0], entries[len(entries)-1]
	id, err := last.EntryID()
	require.NoError(t, err)
	enc, err := cbor.CoreDetEncOptions().EncMode()
	require.NoError(t, err)
	content, err := enc.Marshal([]any{uint64(1), uint64(first.NetworkID), uint64(0), first.Epoch, last.Epoch, id[:], raws, nil})
	require.NoError(t, err)
	out, err := enc.Marshal(cbor.RawTag{Number: tbBundleTag, Content: content})
	require.NoError(t, err)
	return out
}

func tbOutcome(err error) string {
	switch {
	case err == nil:
		return "ok"
	case errors.Is(err, ErrTrustBaseV2Signature):
		return "error:signature"
	case errors.Is(err, ErrTrustBaseV2Chain):
		return "error:chain"
	case errors.Is(err, ErrTrustBaseV2Invalid):
		return "error:invalid"
	default:
		return "error:encoding"
	}
}

// tbAppend is the reference history rule (see the comment at the top).
func tbAppend(held []*RootTrustBaseV2, e *RootTrustBaseV2) ([]*RootTrustBaseV2, string) {
	if len(held) == 0 {
		if err := e.VerifyGenesis(); err != nil {
			return held, tbOutcome(err)
		}
		return append(held, e), "appended"
	}
	tip := held[len(held)-1]
	switch {
	case e.Epoch <= tip.Epoch:
		cur := held[e.Epoch-held[0].Epoch]
		a, _ := cur.EntryID()
		b, _ := e.EntryID()
		if a != b {
			return held, "conflict"
		}
		if e.Epoch > held[0].Epoch {
			if err := e.VerifySuccessor(held[e.Epoch-held[0].Epoch-1]); err != nil {
				return held, tbOutcome(err)
			}
		}
		return held, "noop"
	case e.Epoch > tip.Epoch+1:
		return held, "gap"
	}
	if err := e.VerifySuccessor(tip); err != nil {
		return held, tbOutcome(err)
	}
	return append(held, e), "appended"
}

func tbWeighted(t *testing.T, weights ...uint64) *RootTrustBaseV2 {
	g := v2Genesis(t)
	var total uint64
	for i, w := range weights {
		g.RootNodes[i].Stake = w
		total += w
	}
	g.QuorumThreshold = total*2/3 + 1
	return g
}

func TestTrustBaseV2SharedVectors(t *testing.T) {
	v := tbVectors{Spec: []string{
		"Entries are tag 39000, record version 2; entryId = SHA-256(sigBytes); sigBytes is the entry with the signature field encoded as CBOR null.",
		"A complete bundle is tag 39015 with the GetTrustBase response layout [version=1, network, status=0, fromEpoch, effectiveEnd, endEntryID, [entry, ...], null]: each entry a complete tag-39000 entry, consecutive ascending from a genesis entry, endEntryID = entryId of the last; a one-entry bundle holds the genesis entry only (reference: bft-core gettrustbase/bundle.go).",
		"decode: errorClass encoding = the bytes are not a well-formed deterministic version-2 entry; invalid = well-formed but a structure rule fails.",
		"history: outcome per step per the append rule in types/root_trust_base_v2_vectors_test.go; finalEntryIds is the held chain afterwards.",
		"weightedQuorum: signatures by members of the named committee entry over the entry's sigBytes; the successor is valid iff all signers are members with valid 65-byte low-S recoverable signatures and the signed weight reaches the committee threshold.",
		"Keys: member i (a, b, c, d) has the private key made of 32 bytes of value i (1..4). Test keys only.",
	}}

	g := v2Genesis(t)
	e2 := v2Next(t, g, "a", "b", "c")
	e2abd := v2Next(t, g, "a", "b", "d") // same entry, another valid signature subset
	e3 := v2Next(t, e2, "a", "b", "c")
	add := func(name string, e *RootTrustBaseV2) {
		sb, err := e.SigBytes()
		require.NoError(t, err)
		v.Entries = append(v.Entries, tbVecEntry{name, tbHex(tbEncode(t, e)), tbID(t, e), tbHex(sb)})
	}
	add("genesis", g)
	add("epoch2-signed-abc", e2)
	add("epoch2-signed-abd", e2abd)
	add("epoch3-signed-abc", e3)
	require.Equal(t, tbID(t, e2), tbID(t, e2abd), "two signature subsets, one identity")

	// decode cases
	good := tbEncode(t, e2)
	dec := func(name string, in []byte, valid bool, class string) {
		_, err := DecodeRootTrustBaseV2(in)
		if valid {
			require.NoError(t, err, name)
		} else {
			require.Error(t, err, name)
			require.Equal(t, "error:"+class, tbOutcome(err), name)
		}
		v.Decode = append(v.Decode, tbVecDecode{name, tbHex(in), valid, class})
	}
	dec("genesis", tbEncode(t, g), true, "")
	dec("epoch2", good, true, "")
	dec("trailing byte", append(append([]byte{}, good...), 0), false, "encoding")
	dec("truncated", good[:len(good)-1], false, "encoding")
	dec("wrong tag", append([]byte{0xd9, 0x98, 0x59}, good[3:]...), false, "encoding")
	dec("untagged", good[3:], false, "encoding")
	dec("version 1", rawEntry(t, func(f []any) []any { f[0] = uint64(1); return f }), false, "encoding")
	dec("extra field", rawEntry(t, func(f []any) []any { return append(f, uint64(7)) }), false, "encoding")
	dec("signatures missing", rawEntry(t, func(f []any) []any { return f[:len(f)-1] }), false, "encoding")
	dec("empty state hash", rawEntry(t, func(f []any) []any { f[6] = []byte{}; return f }), false, "encoding")
	dec("quorum threshold 2 of 4", rawEntry(t, func(f []any) []any { f[5] = uint64(2); return f }), false, "invalid")
	dec("network id zero", rawEntry(t, func(f []any) []any { f[1] = uint64(0); return f }), false, "invalid")
	dec("epoch zero", rawEntry(t, func(f []any) []any { f[2] = uint64(0); return f }), false, "invalid")
	dec("genesis predecessor with signatures", rawEntry(t, func(f []any) []any { f[8] = make([]byte, 32); return f }), false, "invalid")
	dec("non-genesis without signatures", rawEntry(t, func(f []any) []any { f[9] = nil; return f }), false, "invalid")

	// bundles
	bun := func(name string, es ...*RootTrustBaseV2) {
		var ids []string
		for _, e := range es {
			ids = append(ids, tbID(t, e))
		}
		v.Bundles = append(v.Bundles, tbVecBundle{name, tbHex(tbBundle(t, es...)), ids})
	}
	bun("one-entry bundle (genesis only)", g)
	bun("three entries, epochs 1..3", g, e2, e3)

	// history
	hist := func(name string, entries ...*RootTrustBaseV2) {
		h := tbVecHistory{Name: name}
		var held []*RootTrustBaseV2
		for _, e := range entries {
			var out string
			held, out = tbAppend(held, e)
			h.Steps = append(h.Steps, tbVecStep{tbHex(tbEncode(t, e)), out})
		}
		for _, e := range held {
			h.Final = append(h.Final, tbID(t, e))
		}
		v.History = append(v.History, h)
	}
	conflict := v2Next(t, g, "a", "b", "c")
	conflict.EpochStart++
	conflict.Signatures = nil
	for i, id := range []string{"a", "b", "c"} {
		require.NoError(t, conflict.Sign(id, v2Key(t, byte(i+1))))
	}
	weak := v2Next(t, g, "a", "b") // 2 of 4, threshold 3
	badsig := v2Next(t, g, "a", "b", "c")
	badsig.Signatures["c"] = append([]byte{}, badsig.Signatures["a"]...)
	stranger := v2Next(t, g, "a", "b", "c")
	stranger.Signatures["z"] = stranger.Signatures["a"]
	badlink := v2Next(t, g)
	badlink.PreviousEntryID = bytes.Repeat([]byte{9}, 32)
	badlink.Signatures = nil
	for i, id := range []string{"a", "b", "c"} {
		require.NoError(t, badlink.Sign(id, v2Key(t, byte(i+1))))
	}
	hist("genesis, then epochs 2 and 3", g, e2, e3)
	hist("same epoch again with another valid signature subset is a noop", g, e2, e2abd)
	hist("re-sent held entry is a noop", g, e2, e2)
	hist("epoch 3 without epoch 2 is a gap", g, e3)
	hist("a different entry for a held epoch is a conflict", g, e2, conflict)
	hist("fewer signatures than the threshold", g, weak)
	hist("a wrong signature", g, badsig)
	hist("a signature of a non-member fails the whole entry", g, stranger)
	hist("a wrong predecessor link", g, badlink)
	hist("a non-genesis first entry", e2)
	hist("a bad witness for a held epoch is an error, not a noop", g, e2, badsig)

	// weighted quorum: weights a=5 b=1 c=1 d=1, total 8, threshold 6
	wg := tbWeighted(t, 5, 1, 1, 1)
	add("weighted-genesis-5-1-1-1", wg)
	try := func(name string, signers ...string) {
		n := v2Next(t, wg)
		n.QuorumThreshold = 3
		n.Signatures = nil
		for _, id := range signers {
			require.NoError(t, n.Sign(id, v2Key(t, byte(map[string]int{"a": 1, "b": 2, "c": 3, "d": 4}[id]))))
		}
		var w uint64
		for _, id := range signers {
			for _, m := range wg.RootNodes {
				if m.NodeID == id {
					w += m.Stake
				}
			}
		}
		err := n.VerifySuccessor(wg)
		valid := w >= wg.QuorumThreshold
		if valid {
			require.NoError(t, err, name)
		} else {
			require.ErrorIs(t, err, ErrTrustBaseV2Signature, name)
		}
		v.Weighted = append(v.Weighted, tbVecQuorum{name, "weighted-genesis-5-1-1-1", signers, w, wg.QuorumThreshold, valid, tbHex(tbEncode(t, n))})
	}
	try("a alone (weight 5 of 6)", "a")
	try("b, c, d (weight 3: three of four members, below the weight threshold)", "b", "c", "d")
	try("a and b (weight 6)", "a", "b")
	try("a, b, c, d (weight 8)", "a", "b", "c", "d")

	got, err := json.MarshalIndent(v, "", "  ")
	require.NoError(t, err)
	got = append(got, '\n')
	const path = "../testdata/trust-base-v2/v1/vectors.json"
	if os.Getenv("UPDATE_VECTORS") != "" {
		require.NoError(t, os.WriteFile(path, got, 0o644))
	}
	want, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, string(want), string(got), "the committed vectors differ from the Go reference (UPDATE_VECTORS=1 regenerates)")
}
