package types

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/require"
)

// Shared GetTrustBase response vectors (testdata/v1/vectors.json) for the SDK decoders: ranges that do not start at the genesis, paged ranges, every
// non-OK status, and the responses DecodeTrustBaseResponse refuses. The entries are the three-entry chain (epochs 1..3) of the shared trust-base vectors
// (testdata/trust-base-v2/v1/vectors.json, bundle "three entries, epochs 1..3"), so an SDK that holds them can also append them.
//
// Regenerate:  GTB_V2_VECTORS=<path of that file> GTB_UPDATE_VECTORS=1 go test ./types -run TestSharedResponseVectors
// Otherwise the test decodes every committed case and compares it with the case's recorded expectation, which is built from the chain, not from the decoder.
const vectorsFile = "../testdata/trust-base-response/v1/vectors.json"

type responseVectorSet struct {
	Spec    []string             `json:"spec"`
	Entries []string             `json:"entries"` // hex of the three tag-39000 entries, epochs 1..3
	Network uint32               `json:"network"`
	Cases   []responseVectorCase `json:"cases"`
}

type responseVectorCase struct {
	Name string `json:"name"`
	Hex  string `json:"hex"`
	// Accept cases
	Status       *uint8   `json:"status,omitempty"`
	FromEpoch    *uint64  `json:"fromEpoch,omitempty"`
	EffectiveEnd *uint64  `json:"effectiveEnd,omitempty"`
	EndEntryID   *string  `json:"endEntryId,omitempty"` // hex, absent = null
	EntryEpochs  []uint64 `json:"entryEpochs,omitempty"`
	NextEpoch    *uint64  `json:"nextEpoch,omitempty"` // absent = null
	// Reject cases: encoding = not a well-formed deterministic response, response = well-formed but a consistency rule fails
	Error string `json:"error,omitempty"`
}

type rawTrustBaseResp struct {
	_            struct{} `cbor:",toarray"`
	Version      uint32
	Network      NetworkID
	Status       uint8
	FromEpoch    uint64
	EffectiveEnd uint64
	EndEntryID   []byte
	Entries      []cbor.RawMessage
	NextEpoch    *uint64
}

type rawTrustBaseRespNullEntries struct {
	_            struct{} `cbor:",toarray"`
	Version      uint32
	Network      NetworkID
	Status       uint8
	FromEpoch    uint64
	EffectiveEnd uint64
	EndEntryID   []byte
	Entries      []cbor.RawMessage
	NextEpoch    *uint64
}

func trustBaseHx(b []byte) string { return hex.EncodeToString(b) }

func buildVectors(t *testing.T, chainHex []string) responseVectorSet {
	t.Helper()
	require.Len(t, chainHex, 3)
	var raws [][]byte
	var ids [][]byte
	var network NetworkID
	for i, h := range chainHex {
		b, err := hex.DecodeString(h)
		require.NoError(t, err)
		e, err := DecodeRootTrustBaseV2(b)
		require.NoError(t, err)
		require.EqualValues(t, i+1, e.Epoch)
		id, err := e.EntryID()
		require.NoError(t, err)
		raws, ids, network = append(raws, b), append(ids, id[:]), e.NetworkID
	}
	enc := func(r rawTrustBaseResp) []byte {
		if r.Entries == nil {
			r.Entries = []cbor.RawMessage{}
		}
		b, err := Cbor.MarshalTaggedValue(TrustBaseResponseTag, &r)
		require.NoError(t, err)
		return b
	}
	rm := func(idx ...int) []cbor.RawMessage {
		out := []cbor.RawMessage{}
		for _, i := range idx {
			out = append(out, raws[i])
		}
		return out
	}
	u := func(v uint64) *uint64 { return &v }
	st := func(v uint8) *uint8 { return &v }
	sp := func(v string) *string { return &v }
	junk := bytes.Repeat([]byte{0xee}, 32)

	set := responseVectorSet{Network: uint32(network), Entries: chainHex}
	set.Spec = []string{
		"A response is tag 39015 [version=1, network, status, fromEpoch, effectiveEnd, endEntryID|null, [entry, ...], nextEpoch|null] (bft-core gettrustbase/codec.go). Entries are the complete tag-39000 values of the shared trust-base vectors, epochs 1..3 (entries[0..2]); entry ids are their EntryIDs.",
		"Accept cases give the decoded fields; entryEpochs are the epochs of the entries in order. An absent endEntryId or nextEpoch is null.",
		"Status: 0 OK, 1 InvalidRequest, 2 WrongNetwork, 3 NotYetAvailable, 4 HistoryMismatch, 5 LimitTooSmall, 6 Busy, 7 Unavailable; 8 and above are refused. A non-OK response carries no entries and no cursor; its fromEpoch/effectiveEnd/endEntryId are advisory peer metadata (the server fills them for status 3 only), never authenticated.",
		"An OK page: entries non-empty, contiguous ascending, the first at fromEpoch, each linked to its predecessor, all of the response's network, an end entry id present. With no cursor the last entry is the effectiveEnd and endEntryId is its EntryID. With a cursor (nextEpoch) it equals last+1 and is at most effectiveEnd, and endEntryId is a hint that is NOT checked against the entries. Signatures are not verified by the response decode (the history append does that).",
		"Reject cases: error 'encoding' = the bytes are not a well-formed deterministic response; 'response' = well-formed but a rule above fails.",
	}

	ok := func(name string, r rawTrustBaseResp, epochs []uint64) {
		c := responseVectorCase{Name: name, Hex: trustBaseHx(enc(r)), Status: st(r.Status), FromEpoch: u(r.FromEpoch), EffectiveEnd: u(r.EffectiveEnd), EntryEpochs: epochs, NextEpoch: r.NextEpoch}
		if r.EndEntryID != nil {
			c.EndEntryID = sp(trustBaseHx(r.EndEntryID))
		}
		set.Cases = append(set.Cases, c)
	}
	bad := func(name string, b []byte, class string) {
		set.Cases = append(set.Cases, responseVectorCase{Name: name, Hex: trustBaseHx(b), Error: class})
	}
	R := func(status uint8, from, end uint64, endID []byte, entries []cbor.RawMessage, next *uint64) rawTrustBaseResp {
		return rawTrustBaseResp{Version: 1, Network: network, Status: status, FromEpoch: from, EffectiveEnd: end, EndEntryID: endID, Entries: entries, NextEpoch: next}
	}

	// accepted
	ok("complete history from the genesis (the release bundle)", R(0, 1, 3, ids[2], rm(0, 1, 2), nil), []uint64{1, 2, 3})
	ok("range from epoch 2 to the tip", R(0, 2, 3, ids[2], rm(1, 2), nil), []uint64{2, 3})
	ok("range of the tip entry only", R(0, 3, 3, ids[2], rm(2), nil), []uint64{3})
	ok("range of one middle entry served up to a requested end (to=2), no cursor", R(0, 2, 2, ids[1], rm(1), nil), []uint64{2})
	ok("page 1 of a paged range: cursor 3, end id of the snapshot end", R(0, 1, 3, ids[2], rm(0, 1), u(3)), []uint64{1, 2})
	ok("page 1 with an end id that matches nothing: the end id on a cursor page is not checked", R(0, 1, 3, junk, rm(0, 1), u(3)), []uint64{1, 2})
	ok("page 1 of one entry, cursor 2", R(0, 1, 3, ids[2], rm(0), u(2)), []uint64{1})
	ok("page 2, the last page of the paged range", R(0, 3, 3, ids[2], rm(2), nil), []uint64{3})
	ok("page 2 starting mid-history: from 2, cursor 3, effective end 3", R(0, 2, 3, ids[2], rm(1), u(3)), []uint64{2})
	for s := uint8(1); s <= 7; s++ {
		switch s {
		case 3:
		default:
			ok(fmt.Sprintf("status %d (%s), nothing else", s, TrustBaseStatus(s)), R(s, 0, 0, nil, nil, nil), nil)
		}
	}
	ok("status 3 NotYetAvailable: from 4 is past the tip (3): nothing newer", R(3, 4, 3, ids[2], nil, nil), nil)
	ok("status 3 NotYetAvailable: a lagging peer (tip 1) asked from 2", R(3, 2, 1, ids[0], nil, nil), nil)
	ok("status 3 NotYetAvailable: effective end not below from (inconsistent for a caller; still a well-formed response)", R(3, 2, 3, ids[2], nil, nil), nil)
	ok("status 4 HistoryMismatch with advisory metadata", R(4, 2, 3, ids[2], nil, nil), nil)

	// refused: consistency (response)
	forged := func(i int, mut func(*RootTrustBaseV2)) cbor.RawMessage {
		e, err := DecodeRootTrustBaseV2(raws[i])
		require.NoError(t, err)
		mut(e)
		b, err := e.MarshalCBOR()
		require.NoError(t, err)
		_, err = DecodeRootTrustBaseV2(b)
		require.NoError(t, err, "the forged entry is itself well formed")
		return b
	}
	idOfRaw := func(b []byte) []byte {
		e, err := DecodeRootTrustBaseV2(b)
		require.NoError(t, err)
		id, err := e.EntryID()
		require.NoError(t, err)
		return id[:]
	}
	wrongLink := forged(2, func(e *RootTrustBaseV2) { e.PreviousEntryID = junk })
	gapEpoch := forged(2, func(e *RootTrustBaseV2) { e.Epoch = 4 })
	bad("consecutive epochs but the entry does not link to its predecessor (previous entry id is not the EntryID of epoch 2)", enc(R(0, 2, 3, idOfRaw(wrongLink), []cbor.RawMessage{raws[1], wrongLink}, nil)), "response")
	bad("a correctly linked entry whose epoch skips one (3 -> 4)", enc(R(0, 2, 4, idOfRaw(gapEpoch), []cbor.RawMessage{raws[1], gapEpoch}, nil)), "response")
	bad("a cursor page without an end entry id", enc(R(0, 1, 3, nil, rm(0, 1), u(3))), "response")
	bad("OK without entries", enc(R(0, 1, 3, ids[2], nil, nil)), "response")
	bad("OK without an end entry id", enc(R(0, 1, 3, nil, rm(0, 1, 2), nil)), "response")
	bad("first entry is not at fromEpoch", enc(R(0, 1, 3, ids[2], rm(1, 2), nil)), "response")
	bad("a gap in the epochs", enc(R(0, 1, 3, ids[2], rm(0, 2), nil)), "response")
	bad("entries out of order", enc(R(0, 2, 3, ids[2], rm(2, 1), nil)), "response")
	bad("an entry that does not link to its predecessor (epoch 2 repeated as 3)", enc(R(0, 2, 3, ids[2], []cbor.RawMessage{raws[1], raws[1]}, nil)), "response")
	bad("no cursor but the page stops before the effective end", enc(R(0, 1, 3, ids[2], rm(0, 1), nil)), "response")
	bad("cursor is not last+1", enc(R(0, 1, 3, ids[2], rm(0), u(3))), "response")
	bad("cursor beyond the effective end", enc(R(0, 1, 2, ids[1], rm(0), u(3))), "response")
	bad("cursor on a page that ends at the effective end", enc(R(0, 2, 3, ids[2], rm(1, 2), u(4))), "response")
	bad("end entry id differs from the last entry when the page ends at the effective end", enc(R(0, 2, 3, junk, rm(1, 2), nil)), "response")
	bad("an entry of another network than the response", func() []byte { r := R(0, 1, 3, ids[2], rm(0, 1, 2), nil); r.Network = network + 1; return enc(r) }(), "response")
	bad("status 6 carrying an entry", enc(R(6, 0, 0, nil, rm(0), nil)), "response")
	bad("status 3 carrying a cursor", enc(R(3, 4, 3, ids[2], nil, u(5))), "response")
	bad("an entry that is not a version 2 entry (4 junk bytes)", enc(R(0, 1, 1, ids[0], []cbor.RawMessage{{0x44, 1, 2, 3, 4}}, nil)), "response")
	// refused: encoding
	bad("status 8", enc(R(8, 0, 0, nil, nil, nil)), "encoding")
	bad("version 2", func() []byte { r := R(0, 1, 3, ids[2], rm(0, 1, 2), nil); r.Version = 2; return enc(r) }(), "encoding")
	bad("end entry id of 31 bytes", enc(R(0, 1, 3, ids[2][:31], rm(0, 1, 2), nil)), "encoding")
	nul := rawTrustBaseRespNullEntries{Version: 1, Network: network, FromEpoch: 1, EffectiveEnd: 3, EndEntryID: ids[2]}
	nb, err := Cbor.MarshalTaggedValue(TrustBaseResponseTag, &nul)
	require.NoError(t, err)
	bad("entries is null, not an array", nb, "encoding")
	good := enc(R(0, 1, 3, ids[2], rm(0, 1, 2), nil))
	bad("trailing byte after the response", append(append([]byte{}, good...), 0x00), "encoding")
	bad("wrong tag (39014, the request tag)", func() []byte {
		b := append([]byte{}, good...)
		// 39015 = 0x9867, 39014 = 0x9866: the tag head is d9 98 67
		require.Equal(t, []byte{0xd9, 0x98, 0x67}, b[:3])
		b[2] = 0x66
		return b
	}(), "encoding")
	bad("truncated response", good[:len(good)-1], "encoding")
	bad("empty input", []byte{}, "encoding")
	return set
}

func TestSharedResponseVectors(t *testing.T) {
	if os.Getenv("GTB_UPDATE_VECTORS") == "1" {
		src, err := os.ReadFile(os.Getenv("GTB_V2_VECTORS"))
		require.NoError(t, err, "GTB_V2_VECTORS: the shared trust-base-v2 vectors file")
		var in struct {
			Bundles []struct {
				Name string `json:"name"`
				Hex  string `json:"hex"`
			} `json:"bundles"`
		}
		require.NoError(t, json.Unmarshal(src, &in))
		var chain []string
		for _, b := range in.Bundles {
			if b.Name == "three entries, epochs 1..3" {
				raw, err := hex.DecodeString(b.Hex)
				require.NoError(t, err)
				r, es, err := DecodeTrustBaseResponse(raw, TrustBaseLimits{MaxBytes: 1 << 20, MaxEntries: 64})
				require.NoError(t, err)
				require.Len(t, es, 3)
				for _, e := range r.Entries {
					chain = append(chain, trustBaseHx(e))
				}
			}
		}
		set := buildVectors(t, chain)
		out, err := json.MarshalIndent(set, "", "  ")
		require.NoError(t, err)
		require.NoError(t, os.MkdirAll("../testdata/trust-base-response/v1", 0o755))
		require.NoError(t, os.WriteFile(vectorsFile, append(out, '\n'), 0o644))
	}

	data, err := os.ReadFile(vectorsFile)
	require.NoError(t, err)
	var set responseVectorSet
	require.NoError(t, json.Unmarshal(data, &set))
	// the committed file is exactly what the builder makes from its own entries
	again := buildVectors(t, set.Entries)
	require.Equal(t, again, set, "the committed vectors are not the builder's output")

	accepted, refused := 0, 0
	for _, c := range set.Cases {
		raw, err := hex.DecodeString(c.Hex)
		require.NoError(t, err, c.Name)
		resp, entries, derr := DecodeTrustBaseResponse(raw, TrustBaseLimits{MaxBytes: 1 << 20, MaxEntries: 64})
		if c.Error != "" {
			refused++
			require.Error(t, derr, c.Name)
			switch c.Error {
			case "encoding":
				require.True(t, errors.Is(derr, ErrTrustBaseResponseEncoding), "%s: %v", c.Name, derr)
			case "response":
				require.True(t, errors.Is(derr, ErrTrustBaseResponse), "%s: %v", c.Name, derr)
			default:
				t.Fatalf("%s: unknown error class %q", c.Name, c.Error)
			}
			continue
		}
		accepted++
		require.NoError(t, derr, c.Name)
		require.EqualValues(t, *c.Status, resp.Status, c.Name)
		require.Equal(t, *c.FromEpoch, resp.FromEpoch, c.Name)
		require.Equal(t, *c.EffectiveEnd, resp.EffectiveEnd, c.Name)
		if c.EndEntryID == nil {
			require.Nil(t, resp.EndEntryID, c.Name)
		} else {
			require.Equal(t, *c.EndEntryID, trustBaseHx(resp.EndEntryID), c.Name)
		}
		require.Equal(t, c.NextEpoch, resp.NextEpoch, c.Name)
		var epochs []uint64
		for _, e := range entries {
			epochs = append(epochs, e.Epoch)
		}
		require.Equal(t, c.EntryEpochs, epochs, c.Name)
	}
	require.Greater(t, accepted, 15)
	require.Greater(t, refused, 20)
}
