package types

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/fxamacker/cbor/v2"
)

// The GetTrustBase response is the one tagged object a root peer, an aggregator and a release file all use to carry signed trust-base entries
// (RootTrustBaseV2):
//
//	Response = tag 39015 [version=1, network, status, fromEpoch, effectiveEnd, endEntryID|null, entries[], nextEpoch|null]
//
// A page is a contiguous ascending run of entries within explicit entry and byte budgets. A complete release bundle is the same object with status OK,
// fromEpoch = the genesis epoch, effectiveEnd = the release tip and no continuation (see EncodeBundle). The entries are the canonical tagged bytes of
// each entry, embedded verbatim. Servers add no authority: a client authenticates every entry from its own latest held entry or pinned genesis.
//
// The request side (tag 39014, used by the peer protocol) is not part of this package yet; the tag number stays reserved for it.
const (
	// TrustBaseResponseTag is the CBOR tag of the response and of the release bundle.
	TrustBaseResponseTag CborTag = 39015

	// TrustBaseResponseVersion is the response version.
	TrustBaseResponseVersion uint32 = 1

	// DefaultTrustBaseMaxEntries and DefaultTrustBaseMaxResponse are the page caps of a served response.
	DefaultTrustBaseMaxEntries  = 64
	DefaultTrustBaseMaxResponse = 1 << 20

	// MaxTrustBaseEntryBytes bounds one encoded entry in a response and in a stored history: 128 KiB. A full entry (256 members with 128-byte node ids and 256
	// predecessor signatures) is about 93 KiB, 16 members need about 6 KiB; the bound is the largest valid entry with margin, so a valid entry is never
	// refused and no oversize one is ever stored.
	MaxTrustBaseEntryBytes = 128 << 10

	// TrustBaseResponseEnvelopeBound is a bound on the response bytes besides the entries (network, status, epochs, end id, array heads), well above
	// the real size.
	TrustBaseResponseEnvelopeBound = 256

	trustBaseResponseNesting = 16
)

// TrustBaseStatus is the status of a GetTrustBase response.
type TrustBaseStatus uint8

const (
	TrustBaseStatusOK TrustBaseStatus = iota
	TrustBaseStatusInvalidRequest
	TrustBaseStatusWrongNetwork
	TrustBaseStatusNotYetAvailable
	TrustBaseStatusHistoryMismatch
	TrustBaseStatusLimitTooSmall
	TrustBaseStatusBusy
	TrustBaseStatusUnavailable
	trustBaseStatusEnd
)

func (s TrustBaseStatus) String() string {
	names := [...]string{"OK", "InvalidRequest", "WrongNetwork", "NotYetAvailable", "HistoryMismatch", "LimitTooSmall", "Busy", "Unavailable"}
	if int(s) < len(names) {
		return names[s]
	}
	return fmt.Sprintf("TrustBaseStatus(%d)", uint8(s))
}

var (
	ErrTrustBaseResponseEncoding = errors.New("trust base response: invalid encoding")
	ErrTrustBaseResponse         = errors.New("trust base response: invalid response")
	ErrTrustBaseBundle           = errors.New("trust base bundle: not a complete bundle")
	ErrTrustBaseBundleChain      = errors.New("trust base bundle: history does not verify")
)

// TrustBaseResponse is [version=1, network, status, fromEpoch, effectiveEnd, endEntryID|null, entries[], nextEpoch|null]. Entries are the canonical
// tagged entries, embedded verbatim. Zero is never an omission sentinel; null is.
type TrustBaseResponse struct {
	_            struct{} `cbor:",toarray"`
	Version      uint32
	Network      NetworkID
	Status       TrustBaseStatus
	FromEpoch    uint64
	EffectiveEnd uint64
	EndEntryID   []byte
	Entries      []cbor.RawMessage
	NextEpoch    *uint64
}

// TrustBaseLimits bound a response decode. MaxBytes is checked against the input before anything is allocated.
type TrustBaseLimits struct {
	MaxBytes   int
	MaxEntries int
}

// TrustBasePageLimits are the caps of a served page.
var TrustBasePageLimits = TrustBaseLimits{MaxBytes: DefaultTrustBaseMaxResponse, MaxEntries: DefaultTrustBaseMaxEntries}

// trustBaseResponseDecMode bounds arrays by the larger of the entry budget and an entry's own member bound: the entries are embedded as raw items
// whose member lists are arrays too, so tying the limit to the number of entries alone would refuse a valid single entry with a large committee. The
// number of entries itself is checked against the caller's limit explicitly.
func trustBaseResponseDecMode(maxEntries int) cbor.DecMode {
	maxArray := MaxTrustBaseV2Members + 16
	if maxEntries > maxArray {
		maxArray = maxEntries
	}
	m, err := cbor.DecOptions{
		DupMapKey:        cbor.DupMapKeyEnforcedAPF,
		IndefLength:      cbor.IndefLengthForbidden,
		MaxNestedLevels:  trustBaseResponseNesting,
		MaxArrayElements: maxArray,
		MaxMapPairs:      MaxTrustBaseV2Members + 16,
		TagsMd:           cbor.TagsAllowed,
	}.DecMode()
	if err != nil {
		panic(err)
	}
	return m
}

// Encode is the tagged deterministic response; the entries are the caller's exact bytes.
func (r *TrustBaseResponse) Encode() ([]byte, error) {
	cp := *r
	if cp.Entries == nil {
		cp.Entries = []cbor.RawMessage{}
	}
	return Cbor.MarshalTaggedValue(TrustBaseResponseTag, &cp)
}

// DecodeTrustBaseResponse strictly decodes a response and checks its internal consistency: status and cursor rules, and for an OK page a contiguous
// ascending run of structurally valid entries of the response's network, linked by predecessor EntryID, ending at effectiveEnd when no cursor remains.
// It does not verify signatures. It returns the response and, for an OK page, the decoded entries.
func DecodeTrustBaseResponse(data []byte, lim TrustBaseLimits) (*TrustBaseResponse, []*RootTrustBaseV2, error) {
	if lim.MaxBytes <= 0 || lim.MaxEntries <= 0 || len(data) > lim.MaxBytes {
		return nil, nil, fmt.Errorf("%w: %d bytes exceed %d", ErrTrustBaseResponseEncoding, len(data), lim.MaxBytes)
	}
	dm := trustBaseResponseDecMode(lim.MaxEntries)
	var raw cbor.RawTag
	if err := dm.Unmarshal(data, &raw); err != nil {
		return nil, nil, fmt.Errorf("%w: %v", ErrTrustBaseResponseEncoding, err)
	}
	if raw.Number != uint64(TrustBaseResponseTag) {
		return nil, nil, fmt.Errorf("%w: tag %d, expected %d", ErrTrustBaseResponseEncoding, raw.Number, TrustBaseResponseTag)
	}
	var r TrustBaseResponse
	if err := dm.Unmarshal(raw.Content, &r); err != nil {
		return nil, nil, fmt.Errorf("%w: %v", ErrTrustBaseResponseEncoding, err)
	}
	again, err := r.Encode()
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %v", ErrTrustBaseResponseEncoding, err)
	}
	if !bytes.Equal(again, data) {
		return nil, nil, fmt.Errorf("%w: not the deterministic encoding", ErrTrustBaseResponseEncoding)
	}
	if r.Version != TrustBaseResponseVersion {
		return nil, nil, fmt.Errorf("%w: version %d", ErrTrustBaseResponseEncoding, r.Version)
	}
	if r.Status >= trustBaseStatusEnd {
		return nil, nil, fmt.Errorf("%w: status %d", ErrTrustBaseResponseEncoding, r.Status)
	}
	if r.Entries == nil {
		return nil, nil, fmt.Errorf("%w: entries must be an array", ErrTrustBaseResponseEncoding)
	}
	if len(r.Entries) > lim.MaxEntries {
		return nil, nil, fmt.Errorf("%w: %d entries exceed %d", ErrTrustBaseResponse, len(r.Entries), lim.MaxEntries)
	}
	if r.EndEntryID != nil && len(r.EndEntryID) != TrustBaseV2IDLen {
		return nil, nil, fmt.Errorf("%w: end id of %d bytes", ErrTrustBaseResponseEncoding, len(r.EndEntryID))
	}
	if r.Status != TrustBaseStatusOK {
		if len(r.Entries) != 0 || r.NextEpoch != nil {
			return nil, nil, fmt.Errorf("%w: %s carries entries or a cursor", ErrTrustBaseResponse, r.Status)
		}
		return &r, nil, nil
	}
	decoded, err := checkTrustBasePage(&r)
	if err != nil {
		return nil, nil, err
	}
	return &r, decoded, nil
}

func checkTrustBasePage(r *TrustBaseResponse) ([]*RootTrustBaseV2, error) {
	if len(r.Entries) == 0 {
		return nil, fmt.Errorf("%w: an OK response without entries", ErrTrustBaseResponse)
	}
	if r.EndEntryID == nil {
		return nil, fmt.Errorf("%w: no end entry id", ErrTrustBaseResponse)
	}
	out := make([]*RootTrustBaseV2, len(r.Entries))
	var prevID [TrustBaseV2IDLen]byte
	for i, raw := range r.Entries {
		if len(raw) > MaxTrustBaseEntryBytes {
			return nil, fmt.Errorf("%w: entry of %d bytes", ErrTrustBaseResponse, len(raw))
		}
		e, err := DecodeRootTrustBaseV2(raw)
		if err != nil {
			return nil, fmt.Errorf("%w: entry %d: %v", ErrTrustBaseResponse, i, err)
		}
		if e.NetworkID != r.Network {
			return nil, fmt.Errorf("%w: entry %d of network %d in a response for %d", ErrTrustBaseResponse, i, e.NetworkID, r.Network)
		}
		if i == 0 && e.Epoch != r.FromEpoch {
			return nil, fmt.Errorf("%w: first entry is epoch %d, page starts at %d", ErrTrustBaseResponse, e.Epoch, r.FromEpoch)
		}
		if i > 0 {
			if out[i-1].Epoch == ^uint64(0) || e.Epoch != out[i-1].Epoch+1 {
				return nil, fmt.Errorf("%w: epoch %d does not follow %d", ErrTrustBaseResponse, e.Epoch, out[i-1].Epoch)
			}
			if !bytes.Equal(e.PreviousEntryID, prevID[:]) {
				return nil, fmt.Errorf("%w: epoch %d does not link to its predecessor", ErrTrustBaseResponse, e.Epoch)
			}
		}
		id, err := e.EntryID()
		if err != nil {
			return nil, err
		}
		prevID, out[i] = id, e
	}
	last := out[len(out)-1].Epoch
	switch {
	case r.NextEpoch == nil && last != r.EffectiveEnd:
		return nil, fmt.Errorf("%w: page ends at %d without a cursor before the effective end %d", ErrTrustBaseResponse, last, r.EffectiveEnd)
	case r.NextEpoch != nil && (*r.NextEpoch != last+1 || *r.NextEpoch > r.EffectiveEnd):
		return nil, fmt.Errorf("%w: cursor %d after epoch %d (end %d)", ErrTrustBaseResponse, *r.NextEpoch, last, r.EffectiveEnd)
	}
	if last == r.EffectiveEnd && !bytes.Equal(r.EndEntryID, prevID[:]) {
		return nil, fmt.Errorf("%w: end entry id differs from the last entry", ErrTrustBaseResponse)
	}
	return out, nil
}
