package types

import (
	"fmt"

	"github.com/fxamacker/cbor/v2"
)

// A complete release bundle is one TrustBaseResponse with status OK, fromEpoch = the genesis epoch, effectiveEnd = the release tip, endEntryID =
// EntryID(tip), every entry in ascending order and no cursor. It is the same object, tag and entry encoding as a page; only the size policy differs:
// a served page is capped at 64 entries / 1 MiB, a bundle is bounded by an explicit budget the release supplies, never a fixed history length.

// TrustBaseBundle is a decoded complete history.
type TrustBaseBundle struct {
	Network NetworkID
	Raw     [][]byte // the canonical bytes of each entry, ascending from the genesis
	Entries []*RootTrustBaseV2
}

// Tip is the release tip.
func (b *TrustBaseBundle) Tip() *RootTrustBaseV2 { return b.Entries[len(b.Entries)-1] }

// EncodeTrustBaseBundle packs a history (ascending, genesis first, canonical entry bytes) into the one tagged response. It fails on a gap, a
// duplicate or a broken link rather than shortening the history, and proves what it wrote with the decoder that loads it.
func EncodeTrustBaseBundle(raw [][]byte) ([]byte, error) {
	if len(raw) == 0 {
		return nil, fmt.Errorf("%w: no entries", ErrTrustBaseBundle)
	}
	entries := make([]cbor.RawMessage, len(raw))
	for i, r := range raw {
		entries[i] = r
	}
	first, err := DecodeRootTrustBaseV2(raw[0])
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrTrustBaseBundle, err)
	}
	last, err := DecodeRootTrustBaseV2(raw[len(raw)-1])
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrTrustBaseBundle, err)
	}
	id, err := last.EntryID()
	if err != nil {
		return nil, err
	}
	out, err := (&TrustBaseResponse{Version: TrustBaseResponseVersion, Network: first.NetworkID, Status: TrustBaseStatusOK, FromEpoch: first.Epoch,
		EffectiveEnd: last.Epoch, EndEntryID: id[:], Entries: entries}).Encode()
	if err != nil {
		return nil, err
	}
	if _, err := DecodeTrustBaseBundle(out, TrustBaseLimits{MaxBytes: len(out), MaxEntries: len(raw)}); err != nil {
		return nil, err
	}
	return out, nil
}

// DecodeTrustBaseBundle strictly decodes a complete bundle: status OK, starting at a genesis entry, no cursor, exactly effectiveEnd-genesis+1
// consecutive entries linked by predecessor EntryID, ending at effectiveEnd with the matching endEntryID, nothing after. It checks structure and
// links, not signatures (see VerifyTrustBaseBundle); a final partial-range page is refused even though its cursor is null.
func DecodeTrustBaseBundle(data []byte, lim TrustBaseLimits) (*TrustBaseBundle, error) {
	resp, decoded, err := DecodeTrustBaseResponse(data, lim)
	if err != nil {
		return nil, err
	}
	switch {
	case resp.Status != TrustBaseStatusOK:
		return nil, fmt.Errorf("%w: status %s", ErrTrustBaseBundle, resp.Status)
	case resp.NextEpoch != nil:
		return nil, fmt.Errorf("%w: a continuation cursor", ErrTrustBaseBundle)
	case !decoded[0].IsGenesis():
		return nil, fmt.Errorf("%w: epoch %d is not a genesis entry (a partial range)", ErrTrustBaseBundle, decoded[0].Epoch)
	}
	b := &TrustBaseBundle{Network: resp.Network, Entries: decoded, Raw: make([][]byte, len(resp.Entries))}
	for i, e := range resp.Entries {
		b.Raw[i] = e
	}
	return b, nil
}

// VerifyTrustBaseBundle is the offline verifier: the genesis must be the pinned identity and every later entry must carry a strict quorum of its
// predecessor's members over its unsigned bytes. It needs no node, store or network.
func VerifyTrustBaseBundle(b *TrustBaseBundle, pin [TrustBaseV2IDLen]byte) error {
	g := b.Entries[0]
	if err := g.VerifyGenesis(); err != nil {
		return fmt.Errorf("%w: %v", ErrTrustBaseBundleChain, err)
	}
	id, err := g.EntryID()
	if err != nil || id != pin {
		return fmt.Errorf("%w: the genesis is not the pinned identity", ErrTrustBaseBundleChain)
	}
	for i := 1; i < len(b.Entries); i++ {
		if err := b.Entries[i].VerifySuccessor(b.Entries[i-1]); err != nil {
			return fmt.Errorf("%w: epoch %d: %v", ErrTrustBaseBundleChain, b.Entries[i].Epoch, err)
		}
	}
	return nil
}
