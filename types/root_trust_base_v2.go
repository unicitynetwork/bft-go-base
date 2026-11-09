package types

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"math"
	"slices"
	"unicode/utf8"

	"github.com/fxamacker/cbor/v2"

	abcrypto "github.com/unicitynetwork/bft-go-base/crypto"
	"github.com/unicitynetwork/bft-go-base/types/hex"
)

// RootTrustBaseV2 is the signed Unicity Trust Base entry, record version 2.
//
// Field meanings are those of RootTrustBaseV1 with these changes:
//   - the entry identity is EntryID() = SHA-256(SigBytes()), the hash of the unsigned preimage (signatures encoded as CBOR null), so two valid signature
//     subsets of the same entry have the same identity, and PreviousEntryID links to the predecessor's EntryID;
//   - member weights are positive and bounded (not fixed to 1), the quorum threshold is exactly floor(2W/3)+1 of the total weight W;
//   - decoding is strict: exact arity, exact tag/version, bounded sizes, no duplicate map keys, no trailing bytes, deterministic (canonical) encoding only;
//   - signature verification is strict: an unknown member, a malformed or an invalid signature fails the whole check even when the valid ones reach quorum.
//
// Absent hashes have one form: StateHash and ChangeRecordHash are either absent (nil, encoded as CBOR null) or exactly 32 bytes. The empty byte string is
// not a valid wire form (DecodeRootTrustBaseV2 refuses it), and an in-memory empty value is encoded as null, so an entry has one EntryID.
//
// The genesis entry (no predecessor) has PreviousEntryID of 32 zero bytes and null Signatures; it is authenticated by an out-of-band pin on its EntryID,
// never by signatures. Every other entry carries the non-empty signature map of the predecessor's members over SigBytes().
//
// RootTrustBaseV1 and its Hash() are unchanged: V1 bytes keep their meaning. There is deliberately no Hash method here.
type RootTrustBaseV2 struct {
	_                struct{}             `cbor:",toarray"`
	Version          Version              `json:"version"`
	NetworkID        NetworkID            `json:"networkId"`
	Epoch            uint64               `json:"epoch"`
	EpochStart       uint64               `json:"epochStartRound"`  // root chain round at which the epoch begins
	RootNodes        []*NodeInfo          `json:"rootNodes"`        // members; NodeInfo.Stake is the member's voting weight
	QuorumThreshold  uint64               `json:"quorumThreshold"`  // exactly floor(2W/3)+1
	StateHash        hex.Bytes            `json:"stateHash"`        // empty or 32 bytes
	ChangeRecordHash hex.Bytes            `json:"changeRecordHash"` // empty or 32 bytes
	PreviousEntryID  hex.Bytes            `json:"previousEntryId"`  // 32 bytes: the predecessor's EntryID, zero for the genesis entry
	Signatures       map[string]hex.Bytes `json:"signatures"`       // predecessor members' signatures over SigBytes(); nil for the genesis entry
}

const (
	// TrustBaseV2Version is the record version of RootTrustBaseV2.
	TrustBaseV2Version Version = 2

	// MaxTrustBaseV2Members bounds the member list while decoding (allocation bound). Deployments admit far fewer; a profile limit is enforced by the caller.
	MaxTrustBaseV2Members = 256
	// MaxTrustBaseV2NodeIDLen bounds a node identifier in bytes.
	MaxTrustBaseV2NodeIDLen = 128
	// MaxTrustBaseV2Weight bounds one member's weight so that the sum over MaxTrustBaseV2Members cannot overflow.
	MaxTrustBaseV2Weight = uint64(1) << 40

	// TrustBaseV2IDLen is the length of an EntryID and of the state/change hashes when present.
	TrustBaseV2IDLen = sha256.Size
)

var (
	ErrTrustBaseV2Encoding  = errors.New("trust base v2: invalid encoding")
	ErrTrustBaseV2Invalid   = errors.New("trust base v2: invalid entry")
	ErrTrustBaseV2Chain     = errors.New("trust base v2: does not extend the predecessor")
	ErrTrustBaseV2Signature = errors.New("trust base v2: signature check failed")

	trustBaseV2DecMode = mustDecMode(cbor.DecOptions{
		DupMapKey:        cbor.DupMapKeyEnforcedAPF,
		IndefLength:      cbor.IndefLengthForbidden,
		MaxNestedLevels:  8,
		MaxArrayElements: MaxTrustBaseV2Members + 16,
		MaxMapPairs:      MaxTrustBaseV2Members + 16,
		TagsMd:           cbor.TagsAllowed,
	})
)

func mustDecMode(o cbor.DecOptions) cbor.DecMode {
	m, err := o.DecMode()
	if err != nil {
		panic(err)
	}
	return m
}

// NewRootTrustBaseV2 returns an empty version-2 value for decoding.
func NewRootTrustBaseV2() *RootTrustBaseV2 { return &RootTrustBaseV2{Version: TrustBaseV2Version} }

// DecodeRootTrustBaseV2 strictly decodes a tagged version-2 entry: exact tag, version and arity, bounded sizes, no duplicate map keys, no trailing bytes, and
// the input must be the deterministic encoding of the decoded value (so every entry has exactly one byte form). It validates the entry's structure
// (Validate) but not its signatures.
func DecodeRootTrustBaseV2(data []byte) (*RootTrustBaseV2, error) {
	var raw cbor.RawTag
	if err := trustBaseV2DecMode.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrTrustBaseV2Encoding, err)
	}
	if raw.Number != UnicityTrustBaseTag {
		return nil, fmt.Errorf("%w: tag %d, expected %d", ErrTrustBaseV2Encoding, raw.Number, UnicityTrustBaseTag)
	}
	type alias RootTrustBaseV2
	var out RootTrustBaseV2
	if err := trustBaseV2DecMode.Unmarshal(raw.Content, (*alias)(&out)); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrTrustBaseV2Encoding, err)
	}
	if out.Version != TrustBaseV2Version {
		return nil, fmt.Errorf("%w: version %d, expected %d", ErrTrustBaseV2Encoding, out.Version, TrustBaseV2Version)
	}
	// an absent hash is null, never an empty byte string (that would be a second byte form, and a second EntryID, of the same entry)
	if out.StateHash != nil && len(out.StateHash) == 0 || out.ChangeRecordHash != nil && len(out.ChangeRecordHash) == 0 {
		return nil, fmt.Errorf("%w: an absent hash is null, not an empty byte string", ErrTrustBaseV2Encoding)
	}
	again, err := out.MarshalCBOR()
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrTrustBaseV2Encoding, err)
	}
	if !bytes.Equal(again, data) {
		return nil, fmt.Errorf("%w: not the deterministic encoding", ErrTrustBaseV2Encoding)
	}
	if err := out.Validate(); err != nil {
		return nil, err
	}
	return &out, nil
}

func (r *RootTrustBaseV2) MarshalCBOR() ([]byte, error) {
	if r.Version != TrustBaseV2Version {
		return nil, fmt.Errorf("%w: version %d, expected %d", ErrTrustBaseV2Encoding, r.Version, TrustBaseV2Version)
	}
	// the canonical absent hash is null: an empty value is normalised to nil so that nil and empty give the same bytes and the same EntryID
	c := *r
	if len(c.StateHash) == 0 {
		c.StateHash = nil
	}
	if len(c.ChangeRecordHash) == 0 {
		c.ChangeRecordHash = nil
	}
	type alias RootTrustBaseV2
	return Cbor.MarshalTaggedValue(UnicityTrustBaseTag, (*alias)(&c))
}

func (r *RootTrustBaseV2) UnmarshalCBOR(data []byte) error {
	dec, err := DecodeRootTrustBaseV2(data)
	if err != nil {
		return err
	}
	*r = *dec
	return nil
}

// SigBytes is the tagged deterministic CBOR of the entry with the signature field encoded as null (not removed from the array).
func (r RootTrustBaseV2) SigBytes() ([]byte, error) {
	r.Signatures = nil
	return r.MarshalCBOR()
}

// EntryID is SHA-256(SigBytes()): independent of the signatures, the identity the successor links to and a pin names.
func (r *RootTrustBaseV2) EntryID() ([TrustBaseV2IDLen]byte, error) {
	sb, err := r.SigBytes()
	if err != nil {
		return [TrustBaseV2IDLen]byte{}, err
	}
	return sha256.Sum256(sb), nil
}

// Sign adds the member's signature over SigBytes() to the signature map.
func (r *RootTrustBaseV2) Sign(nodeID string, signer abcrypto.Signer) error {
	if nodeID == "" {
		return errors.New("node identifier is empty")
	}
	if signer == nil {
		return errors.New("signer is nil")
	}
	sb, err := r.SigBytes()
	if err != nil {
		return err
	}
	sig, err := signer.SignBytes(sb)
	if err != nil {
		return fmt.Errorf("signing failed: %w", err)
	}
	if r.Signatures == nil {
		r.Signatures = make(map[string]hex.Bytes)
	}
	r.Signatures[nodeID] = sig
	return nil
}

// IsGenesis reports whether the entry has no predecessor (zero PreviousEntryID). Validate ties this to the signature field being null.
func (r *RootTrustBaseV2) IsGenesis() bool {
	return len(r.PreviousEntryID) == TrustBaseV2IDLen && bytes.Equal(r.PreviousEntryID, make([]byte, TrustBaseV2IDLen))
}

// Validate checks the entry's structure, not its signatures: version, epoch >= 1, members (sorted by raw node-ID bytes, unique, valid compressed keys,
// positive bounded weights, bounded count), the exact quorum threshold, hash lengths, and genesis (zero predecessor, null signatures) versus
// non-genesis (32-byte predecessor, non-empty signature map).
func (r *RootTrustBaseV2) Validate() error {
	bad := func(format string, a ...any) error {
		return fmt.Errorf("%w: "+format, append([]any{ErrTrustBaseV2Invalid}, a...)...)
	}
	if r == nil {
		return bad("nil entry")
	}
	if r.Version != TrustBaseV2Version {
		return bad("version %d", r.Version)
	}
	if r.Epoch == 0 {
		return bad("epoch is zero")
	}
	// network ids are 1..=0xffff (the Rust and JS SDKs refuse 0 as well); 0 is the unset value
	if r.NetworkID == 0 {
		return bad("network id is zero")
	}
	n := len(r.RootNodes)
	if n == 0 || n > MaxTrustBaseV2Members {
		return bad("%d members (1..%d)", n, MaxTrustBaseV2Members)
	}
	var total uint64
	keys := make(map[string]string, n)
	for i, m := range r.RootNodes {
		if m == nil {
			return bad("member %d is nil", i)
		}
		if m.NodeID == "" || len(m.NodeID) > MaxTrustBaseV2NodeIDLen || !utf8.ValidString(m.NodeID) {
			return bad("member %d: node id is empty, too long or not UTF-8", i)
		}
		if i > 0 && r.RootNodes[i-1].NodeID >= m.NodeID {
			return bad("members are not strictly sorted by node id at %q", m.NodeID)
		}
		if m.Stake == 0 || m.Stake > MaxTrustBaseV2Weight {
			return bad("member %q: weight %d outside 1..%d", m.NodeID, m.Stake, MaxTrustBaseV2Weight)
		}
		if _, err := abcrypto.NewVerifierSecp256k1(m.SigKey); err != nil {
			return bad("member %q: %v", m.NodeID, err)
		}
		// 33-byte compressed keys have one encoding per point, so a byte comparison finds a repeated key: one key holder must not count for several members
		if other, dup := keys[string(m.SigKey)]; dup {
			return bad("members %q and %q share a signing key", other, m.NodeID)
		}
		keys[string(m.SigKey)] = m.NodeID
		total += m.Stake // cannot overflow: at most 256 * 2^40
	}
	if want := total*2/3 + 1; r.QuorumThreshold != want {
		return bad("quorum threshold %d, expected %d for total weight %d", r.QuorumThreshold, want, total)
	}
	for name, h := range map[string]hex.Bytes{"stateHash": r.StateHash, "changeRecordHash": r.ChangeRecordHash} {
		if len(h) != 0 && len(h) != TrustBaseV2IDLen {
			return bad("%s is %d bytes (0 or %d)", name, len(h), TrustBaseV2IDLen)
		}
	}
	if len(r.PreviousEntryID) != TrustBaseV2IDLen {
		return bad("previous entry id is %d bytes", len(r.PreviousEntryID))
	}
	if r.IsGenesis() {
		if r.Signatures != nil {
			return bad("the genesis entry carries signatures")
		}
	} else if len(r.Signatures) == 0 {
		return bad("a non-genesis entry has no signatures")
	}
	return nil
}

// VerifyQuorumSignatures checks signatures by this entry's members over data, strictly: every supplied signature must be from a member and valid
// (a supplied extra that is unknown or invalid fails the check even if the rest reach quorum), and the weight of the signers must reach the threshold.
func (r *RootTrustBaseV2) VerifyQuorumSignatures(data []byte, signatures map[string]hex.Bytes) error {
	var weight uint64
	for nodeID, sig := range signatures {
		w, err := r.VerifySignature(data, sig, nodeID)
		if err != nil {
			return fmt.Errorf("%w: %v", ErrTrustBaseV2Signature, err)
		}
		if w > math.MaxUint64-weight {
			return fmt.Errorf("%w: weight overflow", ErrTrustBaseV2Signature)
		}
		weight += w // map keys are unique, so every member counts once
	}
	if weight < r.QuorumThreshold {
		return fmt.Errorf("%w: quorum not reached, signed weight %d, threshold %d", ErrTrustBaseV2Signature, weight, r.QuorumThreshold)
	}
	return nil
}

// VerifySignature verifies one member's signature and returns the member's weight. The signature must be a canonical recoverable signature: exactly
// 65 bytes, low-S, a recovery id that recovers to the member's key (the crypto.Verifier.VerifyBytes rule).
// The 64-byte compact form is not accepted for UTB entries.
func (r *RootTrustBaseV2) VerifySignature(data []byte, sig []byte, nodeID string) (uint64, error) {
	i, found := slices.BinarySearchFunc(r.RootNodes, nodeID, func(m *NodeInfo, id string) int { return bytes.Compare([]byte(m.NodeID), []byte(id)) })
	if !found {
		return 0, fmt.Errorf("signer %q is not a member", nodeID)
	}
	verifier, err := r.RootNodes[i].SigVerifier()
	if err != nil {
		return 0, fmt.Errorf("signer %q: %w", nodeID, err)
	}
	if err := verifier.VerifyBytes(sig, data); err != nil {
		return 0, fmt.Errorf("signer %q: %w", nodeID, err)
	}
	return r.RootNodes[i].Stake, nil
}

// VerifyGenesis checks a genesis entry's structure (zero predecessor, null signatures). Its authority is a pin on its EntryID, which the caller compares.
func (r *RootTrustBaseV2) VerifyGenesis() error {
	if err := r.Validate(); err != nil {
		return err
	}
	if !r.IsGenesis() {
		return fmt.Errorf("%w: not a genesis entry", ErrTrustBaseV2Invalid)
	}
	return nil
}

// VerifySuccessor checks that r is a valid entry extending prev: same network, epoch prev+1, a later start round, PreviousEntryID equal to
// prev.EntryID(), and a strict quorum of prev's members signing SigBytes().
func (r *RootTrustBaseV2) VerifySuccessor(prev *RootTrustBaseV2) error {
	if prev == nil {
		return fmt.Errorf("%w: no predecessor", ErrTrustBaseV2Chain)
	}
	if err := r.Validate(); err != nil {
		return err
	}
	if r.IsGenesis() {
		return fmt.Errorf("%w: a genesis entry has no predecessor", ErrTrustBaseV2Chain)
	}
	if r.NetworkID != prev.NetworkID {
		return fmt.Errorf("%w: network %d, predecessor %d", ErrTrustBaseV2Chain, r.NetworkID, prev.NetworkID)
	}
	if prev.Epoch == math.MaxUint64 || r.Epoch != prev.Epoch+1 {
		return fmt.Errorf("%w: epoch %d, predecessor %d", ErrTrustBaseV2Chain, r.Epoch, prev.Epoch)
	}
	if r.EpochStart <= prev.EpochStart {
		return fmt.Errorf("%w: epoch start %d, predecessor %d", ErrTrustBaseV2Chain, r.EpochStart, prev.EpochStart)
	}
	id, err := prev.EntryID()
	if err != nil {
		return err
	}
	if !bytes.Equal(r.PreviousEntryID, id[:]) {
		return fmt.Errorf("%w: previous entry id does not match", ErrTrustBaseV2Chain)
	}
	sb, err := r.SigBytes()
	if err != nil {
		return err
	}
	return prev.VerifyQuorumSignatures(sb, r.Signatures)
}

func (r *RootTrustBaseV2) GetVersion() Version        { return TrustBaseV2Version }
func (r *RootTrustBaseV2) GetNetworkID() NetworkID    { return r.NetworkID }
func (r *RootTrustBaseV2) GetEpoch() uint64           { return r.Epoch }
func (r *RootTrustBaseV2) GetEpochStart() uint64      { return r.EpochStart }
func (r *RootTrustBaseV2) GetQuorumThreshold() uint64 { return r.QuorumThreshold }
func (r *RootTrustBaseV2) GetRootNodes() []*NodeInfo  { return r.RootNodes }

// GetMaxFaultyNodes is the largest total weight that may be faulty without reaching the threshold, W - threshold. The sum is unchecked: it is safe only
// on an entry that passed Validate (weights are bounded there); every decoded entry has.
func (r *RootTrustBaseV2) GetMaxFaultyNodes() uint64 {
	var total uint64
	for _, m := range r.RootNodes {
		total += m.Stake
	}
	if total < r.QuorumThreshold {
		return 0
	}
	return total - r.QuorumThreshold
}

var _ RootTrustBase = (*RootTrustBaseV2)(nil)
