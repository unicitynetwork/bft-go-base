package types

import (
	"crypto"
	"fmt"
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"

	abcrypto "github.com/unicitynetwork/bft-go-base/crypto"
	"github.com/unicitynetwork/bft-go-base/types/hex"
)

func TestNodeInfo_IsValid(t *testing.T) {
	keys := genKeys(1)
	validNodeInfo := func() *NodeInfo {
		return &NodeInfo{
			NodeID: "test",
			SigKey: keys["1"].publicKey,
			Stake:  1,
		}
	}

	n := validNodeInfo()
	require.NoError(t, n.IsValid())

	n = validNodeInfo()
	n.Stake = 0
	require.EqualError(t, n.IsValid(), `node must have stake == 1`)
	n.Stake = 2
	require.EqualError(t, n.IsValid(), `node must have stake == 1`)

	n = validNodeInfo()
	n.NodeID = ""
	require.ErrorContains(t, n.IsValid(), "node identifier is empty")

	n = validNodeInfo()
	n.SigKey = nil
	require.ErrorContains(t, n.IsValid(), "signing key is empty")

	n = validNodeInfo()
	n.SigKey = []byte{1}
	require.ErrorContains(t, n.IsValid(), "signing key is invalid")
}

func TestNewTrustBaseGenesis(t *testing.T) {
	keys := genKeys(4)
	type args struct {
		nodes               []*NodeInfo
		unicityTreeRootHash []byte
		opts                []Option
	}
	tests := []struct {
		name       string
		args       args
		verifyFunc func(t *testing.T, tb *RootTrustBaseV1)
		wantErrStr string
	}{
		{
			name:       "empty nodes list",
			args:       args{nodes: nil, unicityTreeRootHash: []byte{1}},
			wantErrStr: "nodes list is empty",
		},
		{
			name: "default settings ok",
			args: args{
				nodes: []*NodeInfo{
					{NodeID: "1", SigKey: keys["1"].publicKey, Stake: 1},
					{NodeID: "2", SigKey: keys["2"].publicKey, Stake: 1},
					{NodeID: "3", SigKey: keys["3"].publicKey, Stake: 1},
				},
				unicityTreeRootHash: []byte{1},
			},
			verifyFunc: func(t *testing.T, tb *RootTrustBaseV1) {
				// verify values
				require.EqualValues(t, 0, tb.Epoch)
				require.EqualValues(t, 0, tb.EpochStart)
				require.Len(t, tb.RootNodes, 3)
				require.EqualValues(t, 3, tb.QuorumThreshold)
				require.EqualValues(t, hex.Bytes(nil), tb.StateHash)
				require.Nil(t, tb.ChangeRecordHash)
				require.Nil(t, tb.PreviousEntryHash)
				require.Empty(t, tb.Signatures)

				// verify methods
				require.EqualValues(t, 3, tb.GetQuorumThreshold())
				require.EqualValues(t, 0, tb.GetMaxFaultyNodes())
				v1, err := tb.getRootNode("1").SigVerifier()
				require.NoError(t, err)
				v2, err := tb.getRootNode("2").SigVerifier()
				require.NoError(t, err)
				v3, err := tb.getRootNode("3").SigVerifier()
				require.NoError(t, err)
				require.Equal(t, keys["1"].verifier, v1)
				require.Equal(t, keys["2"].verifier, v2)
				require.Equal(t, keys["3"].verifier, v3)
			},
		},
		{
			name: "custom quorum threshold ok (4 of 4 nodes)",
			args: args{
				nodes: []*NodeInfo{
					{
						NodeID: "1",
						SigKey: keys["1"].publicKey,
						Stake:  1,
					},
					{
						NodeID: "2",
						SigKey: keys["2"].publicKey,
						Stake:  1,
					},
					{
						NodeID: "3",
						SigKey: keys["3"].publicKey,
						Stake:  1,
					},
					{
						NodeID: "4",
						SigKey: keys["4"].publicKey,
						Stake:  1,
					},
				},
				unicityTreeRootHash: []byte{1},
				opts:                []Option{WithQuorumThreshold(4)},
			},
			verifyFunc: func(t *testing.T, tb *RootTrustBaseV1) {
				require.EqualValues(t, 4, tb.GetQuorumThreshold())
				require.EqualValues(t, 0, tb.GetMaxFaultyNodes())
			},
		},
		{
			name: "custom quorum threshold too low",
			args: args{
				nodes: []*NodeInfo{
					{
						NodeID: "1",
						SigKey: keys["1"].publicKey,
						Stake:  1,
					},
					{
						NodeID: "2",
						SigKey: keys["2"].publicKey,
						Stake:  1,
					},
					{
						NodeID: "3",
						SigKey: keys["3"].publicKey,
						Stake:  1,
					},
					{
						NodeID: "4",
						SigKey: keys["4"].publicKey,
						Stake:  1,
					},
				},
				unicityTreeRootHash: []byte{1},
				opts:                []Option{WithQuorumThreshold(2)},
			},
			wantErrStr: fmt.Sprintf("quorum threshold must be at least '2/3+1' (min threshold %d got %d)", 3, 2),
		},
		{
			name: "custom quorum threshold too high",
			args: args{
				nodes: []*NodeInfo{
					{
						NodeID: "1",
						SigKey: keys["1"].publicKey,
						Stake:  1,
					},
					{
						NodeID: "2",
						SigKey: keys["2"].publicKey,
						Stake:  1,
					},
					{
						NodeID: "3",
						SigKey: keys["3"].publicKey,
						Stake:  1,
					},
				},
				unicityTreeRootHash: []byte{1},
				opts:                []Option{WithQuorumThreshold(4)},
			},
			wantErrStr: fmt.Sprintf("quorum threshold cannot exceed the total staked amount (max threshold %d got %d)", 3, 4),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tb, err := NewTrustBase(NetworkMainNet, tt.args.nodes, tt.args.opts...)
			if tt.wantErrStr != "" {
				require.ErrorContains(t, err, tt.wantErrStr)
				require.Nil(t, tb)
			} else {
				require.NoError(t, err)
				require.NotNil(t, tb)
			}
			if tt.verifyFunc != nil {
				tt.verifyFunc(t, tb)
			}
		})
	}
}

func TestSignAndVerify(t *testing.T) {
	keys := genKeys(1)
	tb, err := NewTrustBase(
		NetworkMainNet,
		[]*NodeInfo{{NodeID: "1", SigKey: keys["1"].publicKey, Stake: 1}},
	)
	require.NoError(t, err)

	err = tb.Sign("1", keys["1"].signer)
	require.NoError(t, err)
	require.Len(t, tb.Signatures, 1)
	sig := tb.Signatures["1"]
	require.NotEmpty(t, sig)
	sb, err := tb.SigBytes()
	require.NoError(t, err)
	err = keys["1"].verifier.VerifyBytes(sig, sb)
	require.NoError(t, err)
}

func Test_RootTrustBaseV1_CBOR(t *testing.T) {
	keys := genKeys(3)
	tb, err := NewTrustBase(
		NetworkMainNet,
		[]*NodeInfo{
			{NodeID: "1", SigKey: keys["1"].publicKey, Stake: 1},
			{NodeID: "2", SigKey: keys["2"].publicKey, Stake: 1},
			{NodeID: "3", SigKey: keys["3"].publicKey, Stake: 1},
		},
	)
	require.NoError(t, err)

	t.Run("Marshal - ok", func(t *testing.T) {
		data, err := Cbor.Marshal(tb)
		require.NoError(t, err)

		tb2 := &RootTrustBaseV1{}
		err = Cbor.Unmarshal(data, tb2)
		require.NoError(t, err)

		// call SigVerifier() on all nodes so that caches are equal
		for _, rn := range tb.RootNodes {
			_, err := rn.SigVerifier()
			require.NoError(t, err)
		}

		for _, rn := range tb2.RootNodes {
			_, err := rn.SigVerifier()
			require.NoError(t, err)
		}

		require.EqualValues(t, tb, tb2)
	})

	t.Run("Unmarshal - invalid version", func(t *testing.T) {
		tb.Version = 2
		data, err := Cbor.Marshal(tb)
		require.NoError(t, err)

		tb2 := &RootTrustBaseV1{}
		err = Cbor.Unmarshal(data, tb2)
		require.ErrorContains(t, err, "invalid version (type *types.RootTrustBaseV1), expected 1, got 2")
	})
}

type key struct {
	signer    abcrypto.Signer
	verifier  abcrypto.Verifier
	publicKey []byte
}

func genKeys(count int) map[string]key {
	keys := make(map[string]key, count)
	for i := 1; i <= count; i++ {
		nodeID := strconv.Itoa(i)
		signer, _ := abcrypto.NewInMemorySecp256K1Signer()
		verifier, _ := signer.Verifier()
		publicKey, _ := verifier.MarshalPublicKey()
		keys[nodeID] = key{
			signer:    signer,
			verifier:  verifier,
			publicKey: publicKey,
		}
	}
	return keys
}

func NewTrustBaseT(t *testing.T, verifiers ...abcrypto.Verifier) RootTrustBase {
	var nodes []*NodeInfo
	for _, v := range verifiers {
		sigKey, err := v.MarshalPublicKey()
		require.NoError(t, err)
		nodes = append(nodes, &NodeInfo{NodeID: "test", SigKey: sigKey, Stake: 1})
	}
	tb, err := NewTrustBase(NetworkMainNet, nodes)
	require.NoError(t, err)
	return tb
}

func NewTrustBaseFromVerifiers(t *testing.T, verifiers map[string]abcrypto.Verifier) RootTrustBase {
	var nodes []*NodeInfo
	for nodeID, v := range verifiers {
		sigKey, err := v.MarshalPublicKey()
		require.NoError(t, err)
		nodes = append(nodes, &NodeInfo{NodeID: nodeID, SigKey: sigKey, Stake: 1})
	}
	tb, err := NewTrustBase(NetworkMainNet, nodes)
	require.NoError(t, err)
	return tb
}

func TestRootTrustBaseV1_Verify(t *testing.T) {
	keys := genKeys(4)
	nodes := make([]*NodeInfo, 0, len(keys))
	for i := 1; i <= len(keys); i++ {
		nodeID := strconv.Itoa(i)
		nodes = append(nodes, &NodeInfo{NodeID: nodeID, SigKey: keys[nodeID].publicKey, Stake: 1})
	}

	// create trust base for epoch 0
	tb0Signed, err := NewTrustBase(NetworkLocal, nodes, WithEpoch(0), WithEpochStart(5))
	require.NoError(t, err)
	require.EqualValues(t, 3, tb0Signed.QuorumThreshold)

	// sign trust base for epoch 0
	for i := 1; i <= 3; i++ {
		err := tb0Signed.Sign(strconv.Itoa(i), keys[strconv.Itoa(i)].signer)
		require.NoError(t, err)
	}

	// create unsigned trust base for epoch 0
	tb0Unsigned, err := NewTrustBase(NetworkLocal, nodes, WithEpoch(0), WithEpochStart(5))
	require.NoError(t, err)

	// calculate signed trust base hash
	tb0Hash, err := tb0Signed.Hash(crypto.SHA256)
	require.NoError(t, err)

	// create a valid trust base for epoch 1, signed by both previous and current validators
	tb1Signed, err := NewTrustBase(NetworkLocal, nodes,
		WithEpoch(1),
		WithEpochStart(50),
		WithPreviousTrustBaseHash(tb0Hash),
	)
	require.NoError(t, err)
	require.EqualValues(t, 3, tb0Signed.QuorumThreshold)

	for i := 1; i <= 3; i++ {
		err := tb1Signed.Sign(strconv.Itoa(i), keys[strconv.Itoa(i)].signer)
		require.NoError(t, err)
	}
	for i := 1; i <= 3; i++ {
		err = tb1Signed.SignPrevious(strconv.Itoa(i), keys[strconv.Itoa(i)].signer)
		require.NoError(t, err)
	}

	tests := []struct {
		name    string
		prev    *RootTrustBaseV1
		curr    *RootTrustBaseV1
		wantErr string
	}{
		{
			name: "genesis trust base with epoch zero ok",
			prev: nil,
			curr: tb0Signed,
		},
		{
			name:    "genesis trust base without signatures nok",
			prev:    nil,
			curr:    tb0Unsigned,
			wantErr: "failed to verify signatures: quorum not reached, signed_votes=0 quorum_threshold=3",
		},
		{
			name: "genesis trust base with non-zero epoch nok",
			prev: nil,
			curr: func() *RootTrustBaseV1 {
				g := *tb0Signed
				g.Epoch = 1
				return &g
			}(),
			wantErr: "genesis trust base epoch must be 0, got 1",
		},
		{
			name: "extend ok",
			prev: tb0Signed,
			curr: tb1Signed,
		},
		{
			name: "extend with different network id nok",
			prev: tb0Signed,
			curr: func() *RootTrustBaseV1 {
				b := *tb1Signed
				b.NetworkID = b.NetworkID + 1
				return &b
			}(),
			wantErr: "invalid network id, got 4 previous 3",
		},
		{
			name: "extend with same epoch nok",
			prev: tb0Signed,
			curr: func() *RootTrustBaseV1 {
				b := *tb1Signed
				b.Epoch = 0
				return &b
			}(),
			wantErr: "invalid epoch, got 0 previous 0",
		},
		{
			name: "extend with epoch not incremented by 1 nok",
			prev: tb0Signed,
			curr: func() *RootTrustBaseV1 {
				b := *tb1Signed
				b.Epoch = 2
				return &b
			}(),
			wantErr: "invalid epoch, got 2 previous 0",
		},
		{
			name: "extend with same epoch start nok",
			prev: tb0Signed,
			curr: func() *RootTrustBaseV1 {
				b := *tb1Signed
				b.EpochStart = 5
				return &b
			}(),
			wantErr: "invalid epoch start, got 5 previous 5",
		},
		{
			name: "extend with smaller epoch start nok",
			prev: tb0Signed,
			curr: func() *RootTrustBaseV1 {
				b := *tb1Signed
				b.EpochStart = 4
				return &b
			}(),
			wantErr: "invalid epoch start, got 4 previous 5",
		},
		{
			name: "extend with invalid previous hash nok",
			prev: tb0Signed,
			curr: func() *RootTrustBaseV1 {
				b := *tb1Signed
				b.PreviousEntryHash = []byte{1, 2, 3}
				return &b
			}(),
			wantErr: "previous trust base hash does not match",
		},
		{
			name: "extend without current epoch signatures nok",
			prev: tb0Signed,
			curr: func() *RootTrustBaseV1 {
				tb, err := NewTrustBase(NetworkLocal, nodes,
					WithEpoch(1),
					WithEpochStart(50),
					WithPreviousTrustBaseHash(tb0Hash),
				)
				require.NoError(t, err)

				// sign with previous epoch keys
				for i := 1; i <= 3; i++ {
					err := tb.SignPrevious(strconv.Itoa(i), keys[strconv.Itoa(i)].signer)
					require.NoError(t, err)
				}
				return tb
			}(),
			wantErr: "failed to verify signatures: quorum not reached, signed_votes=0 quorum_threshold=3",
		},
		{
			name: "extend without previous epoch signatures nok",
			prev: tb0Signed,
			curr: func() *RootTrustBaseV1 {
				tb, err := NewTrustBase(NetworkLocal, nodes,
					WithEpoch(1),
					WithEpochStart(50),
					WithPreviousTrustBaseHash(tb0Hash),
				)
				require.NoError(t, err)

				// sign with current epoch keys
				for i := 1; i <= 3; i++ {
					err := tb.Sign(strconv.Itoa(i), keys[strconv.Itoa(i)].signer)
					require.NoError(t, err)
				}
				return tb
			}(),
			wantErr: "failed to verify previous epoch signatures: quorum not reached, signed_votes=0 quorum_threshold=3",
		},
		{
			name: "extend with not enough previous epoch signatures nok",
			prev: tb0Signed,
			curr: func() *RootTrustBaseV1 {
				tb, err := NewTrustBase(NetworkLocal, nodes,
					WithEpoch(1),
					WithEpochStart(50),
					WithPreviousTrustBaseHash(tb0Hash),
				)
				require.NoError(t, err)

				// sign with current epoch keys
				for i := 1; i <= 3; i++ {
					err := tb.Sign(strconv.Itoa(i), keys[strconv.Itoa(i)].signer)
					require.NoError(t, err)
				}
				// sign with 2 of 3 required previous epoch keys
				for i := 1; i <= 2; i++ {
					err := tb.SignPrevious(strconv.Itoa(i), keys[strconv.Itoa(i)].signer)
					require.NoError(t, err)
				}
				return tb
			}(),
			wantErr: "failed to verify previous epoch signatures: quorum not reached, signed_votes=2 quorum_threshold=3",
		},
		{
			name: "extend with not enough current epoch signatures nok",
			prev: tb0Signed,
			curr: func() *RootTrustBaseV1 {
				tb, err := NewTrustBase(NetworkLocal, nodes,
					WithEpoch(1),
					WithEpochStart(50),
					WithPreviousTrustBaseHash(tb0Hash),
				)
				require.NoError(t, err)

				// sign with 2 of 3 current epoch keys
				for i := 1; i <= 2; i++ {
					err := tb.Sign(strconv.Itoa(i), keys[strconv.Itoa(i)].signer)
					require.NoError(t, err)
				}
				// sign with 2 of 3 required previous epoch keys
				for i := 1; i <= 2; i++ {
					err := tb.SignPrevious(strconv.Itoa(i), keys[strconv.Itoa(i)].signer)
					require.NoError(t, err)
				}
				return tb
			}(),
			wantErr: "failed to verify signatures: quorum not reached, signed_votes=2 quorum_threshold=3",
		},
		{
			name: "extend with invalid previous epoch signature nok",
			prev: tb0Signed,
			curr: func() *RootTrustBaseV1 {
				tb, err := NewTrustBase(NetworkLocal, nodes,
					WithEpoch(1),
					WithEpochStart(50),
					WithPreviousTrustBaseHash(tb0Hash),
				)
				require.NoError(t, err)

				for i := 1; i <= 3; i++ {
					err := tb.Sign(strconv.Itoa(i), keys[strconv.Itoa(i)].signer)
					require.NoError(t, err)
				}
				for i := 1; i <= 3; i++ {
					err := tb.SignPrevious(strconv.Itoa(i), keys[strconv.Itoa(i)].signer)
					require.NoError(t, err)
				}
				tb.PreviousEpochSignatures["1"][0] ^= 0xff // tamper with signature
				return tb
			}(),
			wantErr: "failed to verify previous epoch signatures: quorum not reached, signed_votes=2 quorum_threshold=3",
		},
		{
			name: "extend with invalid current epoch signature nok",
			prev: tb0Signed,
			curr: func() *RootTrustBaseV1 {
				tb, err := NewTrustBase(NetworkLocal, nodes,
					WithEpoch(1),
					WithEpochStart(50),
					WithPreviousTrustBaseHash(tb0Hash),
				)
				require.NoError(t, err)

				for i := 1; i <= 3; i++ {
					err := tb.Sign(strconv.Itoa(i), keys[strconv.Itoa(i)].signer)
					require.NoError(t, err)
				}
				for i := 1; i <= 3; i++ {
					err := tb.SignPrevious(strconv.Itoa(i), keys[strconv.Itoa(i)].signer)
					require.NoError(t, err)
				}
				tb.Signatures["1"][0] ^= 0xff // tamper with signature
				return tb
			}(),
			wantErr: "failed to verify signatures: quorum not reached, signed_votes=2 quorum_threshold=3",
		},
		{
			name: "extend with signature from node not in previous epoch nok",
			prev: tb0Signed,
			curr: func() *RootTrustBaseV1 {
				tb, err := NewTrustBase(NetworkLocal, nodes,
					WithEpoch(1),
					WithEpochStart(50),
					WithPreviousTrustBaseHash(tb0Hash),
				)
				require.NoError(t, err)

				// sign with current epoch keys
				for i := 1; i <= 3; i++ {
					err := tb.Sign(strconv.Itoa(i), keys[strconv.Itoa(i)].signer)
					require.NoError(t, err)
				}
				// sign with 2 of 3 previous epoch keys
				for i := 1; i <= 2; i++ {
					err := tb.SignPrevious(strconv.Itoa(i), keys[strconv.Itoa(i)].signer)
					require.NoError(t, err)
				}
				// sign with key that is not in tb0Signed
				signer, err := abcrypto.NewInMemorySecp256K1Signer()
				require.NoError(t, err)
				require.NoError(t, tb.SignPrevious("4", signer))

				return tb
			}(),
			wantErr: "failed to verify previous epoch signatures: quorum not reached, signed_votes=2 quorum_threshold=3",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.curr.Verify(tt.prev)
			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)
			} else {
				require.NoError(t, err)
			}
		})
	}
}
