package types

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/require"

	abcrypto "github.com/unicitynetwork/bft-go-base/crypto"
)

func bundleChain(t *testing.T, k int) []*RootTrustBaseV2 {
	out := []*RootTrustBaseV2{v2Genesis(t)}
	for i := 0; i < k; i++ {
		out = append(out, v2Next(t, out[i], "a", "b", "c"))
	}
	return out
}

func bundleRaw(t *testing.T, es []*RootTrustBaseV2) [][]byte {
	out := make([][]byte, len(es))
	for i, e := range es {
		b, err := e.MarshalCBOR()
		require.NoError(t, err)
		out[i] = b
	}
	return out
}

func entryIDOf(t *testing.T, e *RootTrustBaseV2) [TrustBaseV2IDLen]byte {
	id, err := e.EntryID()
	require.NoError(t, err)
	return id
}

var bundleBudget = TrustBaseLimits{MaxBytes: 1 << 24, MaxEntries: 1 << 12}

func u64p(v uint64) *uint64 { return &v }

func TestACompleteBundleBeyondThePageCapsReloadsByteForByte(t *testing.T) {
	es := bundleChain(t, 200) // 201 entries: far beyond a 64-entry page
	file, err := EncodeTrustBaseBundle(bundleRaw(t, es))
	require.NoError(t, err)

	// the same object as a page: not decodable under the page caps, only under the bundle budget
	_, _, err = DecodeTrustBaseResponse(file, TrustBasePageLimits)
	require.Error(t, err)
	b, err := DecodeTrustBaseBundle(file, TrustBaseLimits{MaxBytes: len(file), MaxEntries: 201})
	require.NoError(t, err)
	require.Len(t, b.Entries, 201)
	require.Equal(t, entryIDOf(t, es[200]), entryIDOf(t, b.Tip()))
	again, err := EncodeTrustBaseBundle(b.Raw)
	require.NoError(t, err)
	require.Equal(t, file, again, "exact export/reload bytes")
	require.NoError(t, VerifyTrustBaseBundle(b, entryIDOf(t, es[0])))

	// the byte and entry budgets are checked before decoding / allocating
	_, err = DecodeTrustBaseBundle(file, TrustBaseLimits{MaxBytes: len(file) - 1, MaxEntries: 201})
	require.ErrorIs(t, err, ErrTrustBaseResponseEncoding)
	_, err = DecodeTrustBaseBundle(file, TrustBaseLimits{MaxBytes: len(file), MaxEntries: 200})
	require.ErrorIs(t, err, ErrTrustBaseResponse)
}

// A one-entry bundle (the release file of a fresh network) must carry a committee of the largest admitted size: the array bound of the decoder is not
// tied to the number of entries.
func TestAOneEntryBundleCarriesALargeCommittee(t *testing.T) {
	for _, n := range []int{4, 22, MaxTrustBaseV2Members} {
		g := &RootTrustBaseV2{Version: 2, NetworkID: 5, Epoch: 1, EpochStart: 1, PreviousEntryID: make([]byte, TrustBaseV2IDLen)}
		for i := 1; i <= n; i++ {
			key := append(make([]byte, 30), byte((i+1)>>8), byte(i+1))
			s, err := abcrypto.NewInMemorySecp256K1SignerFromKey(key)
			require.NoError(t, err)
			v, err := s.Verifier()
			require.NoError(t, err)
			pk, err := v.MarshalPublicKey()
			require.NoError(t, err)
			g.RootNodes = append(g.RootNodes, &NodeInfo{NodeID: fmt.Sprintf("n%03d", i), SigKey: pk, Stake: 1})
		}
		g.QuorumThreshold = uint64(n)*2/3 + 1
		raw, err := g.MarshalCBOR()
		require.NoError(t, err, n)
		file, err := EncodeTrustBaseBundle([][]byte{raw})
		require.NoError(t, err, n)
		b, err := DecodeTrustBaseBundle(file, TrustBaseLimits{MaxBytes: len(file), MaxEntries: 1})
		require.NoError(t, err, "%d members", n)
		require.Len(t, b.Entries[0].RootNodes, n)
		require.NoError(t, VerifyTrustBaseBundle(b, entryIDOf(t, g)))
	}
}

func TestABundleThatIsNotCompleteIsRefused(t *testing.T) {
	es := bundleChain(t, 6)
	rs := bundleRaw(t, es)
	enc := func(r *TrustBaseResponse) []byte {
		b, err := r.Encode()
		require.NoError(t, err)
		return b
	}
	mk := func(from, to int, ents ...[]byte) *TrustBaseResponse {
		id := entryIDOf(t, es[to])
		r := &TrustBaseResponse{Version: 1, Network: 5, Status: TrustBaseStatusOK, FromEpoch: uint64(from + 1), EffectiveEnd: uint64(to + 1), EndEntryID: id[:]}
		for _, e := range ents {
			r.Entries = append(r.Entries, e)
		}
		return r
	}
	_, err := DecodeTrustBaseBundle(enc(mk(0, 6, rs...)), bundleBudget)
	require.NoError(t, err)
	cases := map[string][]byte{
		"missing prefix (a partial range ending at the tip)": enc(mk(2, 6, rs[2:]...)),
		"missing middle":   enc(mk(0, 6, append(append([][]byte{}, rs[:3]...), rs[4:]...)...)),
		"duplicate epoch":  enc(mk(0, 6, append(append([][]byte{}, rs[:3]...), rs[2:]...)...)),
		"short of its end": enc(mk(0, 6, rs[:6]...)),
		"wrong end id":     enc(func() *TrustBaseResponse { r := mk(0, 6, rs...); r.EndEntryID = bytes.Repeat([]byte{9}, 32); return r }()),
		"continuation set": enc(func() *TrustBaseResponse {
			r := mk(0, 5, rs[:6]...)
			r.NextEpoch = u64p(7)
			r.EffectiveEnd = 7
			return r
		}()),
		"error status":      enc(&TrustBaseResponse{Version: 1, Network: 5, Status: TrustBaseStatusNotYetAvailable, Entries: []cbor.RawMessage{}}),
		"trailing bytes":    append(enc(mk(0, 6, rs...)), 0),
		"no entries at all": enc(&TrustBaseResponse{Version: 1, Network: 5, Status: TrustBaseStatusOK, Entries: []cbor.RawMessage{}, EndEntryID: bytes.Repeat([]byte{1}, 32)}),
	}
	for name, c := range cases {
		_, err := DecodeTrustBaseBundle(c, bundleBudget)
		require.Error(t, err, name)
	}
	_, err = EncodeTrustBaseBundle(append(append([][]byte{}, rs[:2]...), rs[3:]...))
	require.Error(t, err, "encoding fails on a gap rather than shortening the history")
	_, err = EncodeTrustBaseBundle(nil)
	require.Error(t, err)
}

func TestVerifyTrustBaseBundleOffline(t *testing.T) {
	es := bundleChain(t, 10)
	pin := entryIDOf(t, es[0])
	forced := func(es []*RootTrustBaseV2) *TrustBaseBundle {
		return &TrustBaseBundle{Network: 5, Entries: es, Raw: bundleRaw(t, es)}
	}
	decoded := func(es []*RootTrustBaseV2) *TrustBaseBundle {
		b, err := EncodeTrustBaseBundle(bundleRaw(t, es))
		require.NoError(t, err)
		d, err := DecodeTrustBaseBundle(b, bundleBudget)
		require.NoError(t, err)
		return d
	}
	require.NoError(t, VerifyTrustBaseBundle(decoded(es), pin))
	require.ErrorIs(t, VerifyTrustBaseBundle(decoded(es), [TrustBaseV2IDLen]byte{1}), ErrTrustBaseBundleChain, "wrong pin")

	// a quorum short by one signer
	short := bundleChain(t, 10)
	short[5].Signatures = nil
	require.NoError(t, short[5].Sign("a", v2Key(t, 1)))
	require.NoError(t, short[5].Sign("b", v2Key(t, 2)))
	err := VerifyTrustBaseBundle(forced(short), pin)
	require.ErrorIs(t, err, ErrTrustBaseBundleChain)
	require.Contains(t, err.Error(), "epoch 6")

	// an extra unknown signer fails the entry even though the valid ones reach quorum
	extra := bundleChain(t, 10)
	extra[7].Signatures["stranger"] = bytes.Repeat([]byte{1}, 65)
	require.ErrorIs(t, VerifyTrustBaseBundle(forced(extra), pin), ErrTrustBaseBundleChain)

	// a broken hash link
	linked := bundleChain(t, 10)
	linked[4].PreviousEntryID = bytes.Repeat([]byte{4}, 32)
	require.ErrorIs(t, VerifyTrustBaseBundle(forced(linked), pin), ErrTrustBaseBundleChain)

	// a different chain on the same pin
	other := bundleChain(t, 3)
	other[0].Epoch, other[0].EpochStart = 1, 2
	require.ErrorIs(t, VerifyTrustBaseBundle(forced(other), pin), ErrTrustBaseBundleChain)
}

func TestTrustBaseStatusNames(t *testing.T) {
	require.Equal(t, "OK", TrustBaseStatusOK.String())
	require.Equal(t, "Unavailable", TrustBaseStatusUnavailable.String())
	require.Equal(t, "TrustBaseStatus(99)", TrustBaseStatus(99).String())
}

// The bundles of the shared trust-base vectors (the SDKs decode the same bytes) are accepted by this decoder, re-encode to the same bytes, carry the
// recorded EntryIDs and verify from their own genesis.
func TestTheSharedVectorBundlesDecodeAndReEncodeIdentically(t *testing.T) {
	data, err := os.ReadFile("../testdata/trust-base-v2/v1/vectors.json")
	require.NoError(t, err)
	var in struct {
		Bundles []struct {
			EntryIDs []string `json:"entryIds"`
			Hex      string   `json:"hex"`
			Name     string   `json:"name"`
		} `json:"bundles"`
	}
	require.NoError(t, json.Unmarshal(data, &in))
	require.NotEmpty(t, in.Bundles)
	for _, v := range in.Bundles {
		raw, err := hex.DecodeString(v.Hex)
		require.NoError(t, err, v.Name)
		b, err := DecodeTrustBaseBundle(raw, TrustBaseLimits{MaxBytes: len(raw), MaxEntries: len(v.EntryIDs)})
		require.NoError(t, err, v.Name)
		require.Len(t, b.Entries, len(v.EntryIDs), v.Name)
		for i, e := range b.Entries {
			id := entryIDOf(t, e)
			require.Equal(t, v.EntryIDs[i], hex.EncodeToString(id[:]), v.Name)
		}
		again, err := EncodeTrustBaseBundle(b.Raw)
		require.NoError(t, err, v.Name)
		require.Equal(t, raw, again, v.Name)
		require.NoError(t, VerifyTrustBaseBundle(b, entryIDOf(t, b.Entries[0])), v.Name)
	}
}
