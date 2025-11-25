package types

import (
	"bytes"
	"cmp"
	"crypto"
	"errors"
	"fmt"
	"slices"
	"sync"

	abcrypto "github.com/unicitynetwork/bft-go-base/crypto"
	abhash "github.com/unicitynetwork/bft-go-base/hash"
	"github.com/unicitynetwork/bft-go-base/types/hex"
)

type (
	RootTrustBase interface {
		GetVersion() Version
		GetNetworkID() NetworkID
		GetEpoch() uint64
		GetEpochStart() uint64
		VerifyQuorumSignatures(data []byte, signatures map[string]hex.Bytes) error
		VerifySignature(data []byte, sig []byte, nodeID string) (uint64, error)
		GetQuorumThreshold() uint64
		GetMaxFaultyNodes() uint64
		GetRootNodes() []*NodeInfo
	}

	RootTrustBaseV1 struct {
		_                       struct{}             `cbor:",toarray"`
		Version                 Version              `json:"version"`
		NetworkID               NetworkID            `json:"networkId"`
		Epoch                   uint64               `json:"epoch"`                   // current epoch number
		EpochStart              uint64               `json:"epochStartRound"`         // root chain round number when the epoch begins
		RootNodes               []*NodeInfo          `json:"rootNodes"`               // list of all root nodes for the current epoch
		QuorumThreshold         uint64               `json:"quorumThreshold"`         // amount of coins required to reach consensus, currently each node gets equal amount of voting power i.e. +1 for each node
		StateHash               hex.Bytes            `json:"stateHash"`               // unicity tree root hash
		ChangeRecordHash        hex.Bytes            `json:"changeRecordHash"`        // epoch change request hash
		PreviousEntryHash       hex.Bytes            `json:"previousEntryHash"`       // previous trust base entry hash
		Signatures              map[string]hex.Bytes `json:"signatures"`              // signatures of current epoch validators, over all fields except for the signatures fields itself
		PreviousEpochSignatures map[string]hex.Bytes `json:"previousEpochSignatures"` // signatures of previous epoch validators, over all fields except for this field itself
	}

	NodeInfo struct {
		_      struct{}  `cbor:",toarray"`
		NodeID string    `json:"nodeId"` // node identifier
		SigKey hex.Bytes `json:"sigKey"` // signing key of the node
		Stake  uint64    `json:"stake"`  // amount of staked coins for this node

		// cached signature verifier; private fields are ignored in JSON and CBOR encodings
		sigVerifier     abcrypto.Verifier
		sigVerifierInit sync.Once
	}

	Option func(c *trustBaseConf)

	trustBaseConf struct {
		epoch                 uint64
		epochStart            uint64
		quorumThreshold       uint64
		previousTrustBaseHash hex.Bytes
	}
)

// NewTrustBase creates new unsigned root trust base.
func NewTrustBase(networkID NetworkID, rootNodes []*NodeInfo, opts ...Option) (*RootTrustBaseV1, error) {
	if len(rootNodes) == 0 {
		return nil, errors.New("nodes list is empty")
	}

	// init config
	c := &trustBaseConf{}
	for _, opt := range opts {
		opt(c)
	}

	// Sort rootNodes by NodeID, so that we have a consistent order in every
	// implementation/encoding and we can perform binary search on them.
	slices.SortFunc(rootNodes, func(a, b *NodeInfo) int {
		return cmp.Compare(a.NodeID, b.NodeID)
	})

	// calculate quorum threshold
	var totalStake uint64
	for _, n := range rootNodes {
		totalStake += n.Stake
	}
	minStake := totalStake*2/3 + 1

	if c.quorumThreshold == 0 {
		c.quorumThreshold = minStake // set quorum threshold to minimum if no threshold was configured
	}
	if c.quorumThreshold < minStake {
		return nil, fmt.Errorf("quorum threshold must be at least '2/3+1' (min threshold %d got %d)", minStake, c.quorumThreshold)
	}
	if c.quorumThreshold > totalStake {
		return nil, fmt.Errorf("quorum threshold cannot exceed the total staked amount (max threshold %d got %d)", totalStake, c.quorumThreshold)
	}

	return &RootTrustBaseV1{
		Version:           1,
		NetworkID:         networkID,
		Epoch:             c.epoch,
		EpochStart:        c.epochStart,
		RootNodes:         rootNodes,
		QuorumThreshold:   c.quorumThreshold,
		StateHash:         nil,
		ChangeRecordHash:  nil,
		PreviousEntryHash: c.previousTrustBaseHash,
		Signatures:        make(map[string]hex.Bytes),
	}, nil
}

// WithQuorumThreshold overrides the default 2/3+1 quorum threshold.
func WithQuorumThreshold(threshold uint64) Option {
	return func(c *trustBaseConf) {
		c.quorumThreshold = threshold
	}
}

func WithEpoch(epoch uint64) Option {
	return func(c *trustBaseConf) {
		c.epoch = epoch
	}
}

func WithEpochStart(epochStart uint64) Option {
	return func(c *trustBaseConf) {
		c.epochStart = epochStart
	}
}

func WithPreviousTrustBaseHash(previousTrustBaseHash hex.Bytes) Option {
	return func(c *trustBaseConf) {
		c.previousTrustBaseHash = previousTrustBaseHash
	}
}

// IsValid validates that all fields are correctly set and public keys are correct.
func (n *NodeInfo) IsValid() error {
	if n == nil {
		return errors.New("node info is empty")
	}
	if n.NodeID == "" {
		return errors.New("node identifier is empty")
	}
	// until proper staking is implemented require that all nodes do have equal stake
	// and thus equal vote when determining quorum
	if n.Stake != 1 {
		return errors.New("node must have stake == 1")
	}
	if len(n.SigKey) == 0 {
		return errors.New("signing key is empty")
	}
	if _, err := abcrypto.NewVerifierSecp256k1(n.SigKey); err != nil {
		return fmt.Errorf("signing key is invalid: %w", err)
	}
	return nil
}

func (n *NodeInfo) SigVerifier() (abcrypto.Verifier, error) {
	var err error
	n.sigVerifierInit.Do(func() {
		n.sigVerifier, err = abcrypto.NewVerifierSecp256k1(n.SigKey)
	})
	if err != nil {
		return nil, fmt.Errorf("invalid signing key: %w", err)
	}
	return n.sigVerifier, nil
}

// Sign signs the trust base entry, storing the signature to Signatures map.
func (r *RootTrustBaseV1) Sign(nodeID string, signer abcrypto.Signer) error {
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
	r.Signatures[nodeID] = sig
	return nil
}

// SignPrevious signs the trust base entry, storing the signature to PreviousEpochSignatures map.
func (r *RootTrustBaseV1) SignPrevious(nodeID string, signer abcrypto.Signer) error {
	if nodeID == "" {
		return errors.New("node identifier is empty")
	}
	if signer == nil {
		return errors.New("signer is nil")
	}
	sb, err := r.PreviousEpochSigBytes()
	if err != nil {
		return err
	}
	sig, err := signer.SignBytes(sb)
	if err != nil {
		return fmt.Errorf("signing failed: %w", err)
	}
	if r.PreviousEpochSignatures == nil {
		r.PreviousEpochSignatures = make(map[string]hex.Bytes)
	}
	r.PreviousEpochSignatures[nodeID] = sig
	return nil
}

// Hash hashes the entire structure including the signatures.
func (r *RootTrustBaseV1) Hash(hashAlgo crypto.Hash) ([]byte, error) {
	hasher := abhash.New(hashAlgo.New())
	hasher.Write(r)
	return hasher.Sum()
}

// SigBytes serializes all fields expect for the Signatures and PreviousEpochSignatures fields.
func (r RootTrustBaseV1) SigBytes() ([]byte, error) {
	r.Signatures = nil
	r.PreviousEpochSignatures = nil
	bs, err := r.MarshalCBOR()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal root trust base: %w", err)
	}
	return bs, nil
}

// PreviousEpochSigBytes serializes all fields expect for the PreviousEpochSignatures field.
func (r RootTrustBaseV1) PreviousEpochSigBytes() ([]byte, error) {
	r.PreviousEpochSignatures = nil
	bs, err := r.MarshalCBOR()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal root trust base: %w", err)
	}
	return bs, nil
}

// VerifyQuorumSignatures verifies that the data is signed by enough root nodes so that quorum is reached,
// returns error if quorum is not reached.
func (r *RootTrustBaseV1) VerifyQuorumSignatures(data []byte, signatures map[string]hex.Bytes) error {
	// verify all signatures, calculate quorum
	var quorum uint64
	for nodeID, sig := range signatures {
		if stake, err := r.VerifySignature(data, sig, nodeID); err == nil {
			quorum += stake
		}
	}
	if quorum >= r.QuorumThreshold {
		return nil
	}
	return fmt.Errorf("quorum not reached, signed_votes=%d quorum_threshold=%d", quorum, r.QuorumThreshold)
}

// VerifySignature verifies that the data is signed by the given root validator,
// returns the validator's stake if it is signed.
func (r *RootTrustBaseV1) VerifySignature(data []byte, sig []byte, nodeID string) (uint64, error) {
	verifierNode := r.getRootNode(nodeID)
	if verifierNode == nil {
		return 0, fmt.Errorf("author '%s' is not part of the trust base", nodeID)
	}
	verifier, err := verifierNode.SigVerifier()
	if err != nil {
		return 0, fmt.Errorf("failed to get signature verifier for nodeID=%s: %w", nodeID, err)
	}
	if err := verifier.VerifyBytes(sig, data); err != nil {
		return 0, fmt.Errorf("verify bytes failed: %w", err)
	}
	return verifierNode.Stake, nil
}

// GetQuorumThreshold returns the quorum threshold for the latest trust base entry.
func (r *RootTrustBaseV1) GetQuorumThreshold() uint64 {
	return r.QuorumThreshold
}

// GetMaxFaultyNodes returns max allowed faulty nodes, only works if one node == one vote.
func (r *RootTrustBaseV1) GetMaxFaultyNodes() uint64 {
	return uint64(len(r.RootNodes)) - r.QuorumThreshold
}

func (r *RootTrustBaseV1) GetRootNodes() []*NodeInfo {
	return r.RootNodes
}

func (r *RootTrustBaseV1) GetVersion() Version {
	if r == nil || r.Version == 0 {
		return 1
	}
	return r.Version
}

func (r *RootTrustBaseV1) GetNetworkID() NetworkID {
	return r.NetworkID
}

func (r *RootTrustBaseV1) GetEpoch() uint64 {
	return r.Epoch
}

func (r *RootTrustBaseV1) GetEpochStart() uint64 {
	return r.EpochStart
}

func (r *RootTrustBaseV1) MarshalCBOR() ([]byte, error) {
	type alias RootTrustBaseV1
	if r.Version == 0 {
		r.Version = r.GetVersion()
	}
	return Cbor.MarshalTaggedValue(RootTrustBaseTag, (*alias)(r))
}

func (r *RootTrustBaseV1) UnmarshalCBOR(data []byte) error {
	type alias RootTrustBaseV1
	if err := Cbor.UnmarshalTaggedValue(RootTrustBaseTag, data, (*alias)(r)); err != nil {
		return fmt.Errorf("failed to unmarshal root trust base: %w", err)
	}
	return EnsureVersion(r, r.Version, 1)
}

func (r *RootTrustBaseV1) getRootNode(nodeID string) *NodeInfo {
	idx, found := slices.BinarySearchFunc(r.RootNodes, nodeID, func(nodeInfo *NodeInfo, nodeID string) int {
		return cmp.Compare(nodeInfo.NodeID, nodeID)
	})
	if found {
		return r.RootNodes[idx]
	}
	return nil
}

// Verify verifies the trust base, including the signatures.
//
// Common for all trust bases:
//   - The current epoch signatures must be valid and reach quorum.
//
// Genesis trust base:
//   - Epoch must be zero.
//
// Non-genesis trust base must extend previous trust base:
//   - The network identifiers must match.
//   - The epoch number must be strictly greater than the previous epoch number.
//   - The epoch start round must be strictly greater than the previous epoch start round.
//   - The hash of the previous trust must match the previousEntryHash.
//   - The previous epoch signatures must be valid and reach quorum.
func (r *RootTrustBaseV1) Verify(prev *RootTrustBaseV1) error {
	if err := r.IsValid(prev); err != nil {
		return err
	}
	return r.VerifySignatures(prev)
}

// IsValid verifies the trust base without verifying the signatures.
// Use VerifySignatures to verify the signatures.
func (r *RootTrustBaseV1) IsValid(prev *RootTrustBaseV1) error {
	if prev == nil {
		if r.Epoch != 0 {
			return fmt.Errorf("genesis trust base epoch must be 0, got %d", r.Epoch)
		}
		return nil
	}
	if r.NetworkID != prev.NetworkID {
		return fmt.Errorf("invalid network id, got %d previous %d", r.NetworkID, prev.NetworkID)
	}
	if r.Epoch != prev.Epoch+1 {
		return fmt.Errorf("invalid epoch, got %d previous %d", r.Epoch, prev.Epoch)
	}
	if r.EpochStart <= prev.EpochStart {
		return fmt.Errorf("invalid epoch start, got %d previous %d", r.EpochStart, prev.EpochStart)
	}
	prevHash, err := prev.Hash(crypto.SHA256)
	if err != nil {
		return fmt.Errorf("failed to calculate previous trust base hash: %w", err)
	}
	if !bytes.Equal(r.PreviousEntryHash, prevHash) {
		return errors.New("previous trust base hash does not match")
	}
	return nil
}

// VerifySignatures verifies the trust base is signed by quorum.
func (r *RootTrustBaseV1) VerifySignatures(prev *RootTrustBaseV1) error {
	// verify current epoch signatures
	sigBytes, err := r.SigBytes()
	if err != nil {
		return fmt.Errorf("failed to get sig bytes: %w", err)
	}
	if err := r.VerifyQuorumSignatures(sigBytes, r.Signatures); err != nil {
		return fmt.Errorf("failed to verify signatures: %w", err)
	}

	// verify previous epoch signatures
	if prev != nil {
		prevSigBytes, err := r.PreviousEpochSigBytes()
		if err != nil {
			return fmt.Errorf("failed to get previous epoch sig bytes: %w", err)
		}
		if err := prev.VerifyQuorumSignatures(prevSigBytes, r.PreviousEpochSignatures); err != nil {
			return fmt.Errorf("failed to verify previous epoch signatures: %w", err)
		}
	}
	return nil
}
