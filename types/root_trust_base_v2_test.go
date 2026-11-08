package types

import (
	"bytes"
	"crypto"
	"encoding/hex"
	"fmt"
	"slices"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/require"

	abcrypto "github.com/unicitynetwork/bft-go-base/crypto"
	abhex "github.com/unicitynetwork/bft-go-base/types/hex"
)

// fixed keys: secp256k1 signing is deterministic (RFC 6979), so the vectors below are reproducible.
func v2Key(t *testing.T, i byte) abcrypto.Signer {
	k := bytes.Repeat([]byte{i}, 32)
	s, err := abcrypto.NewInMemorySecp256K1SignerFromKey(k)
	require.NoError(t, err)
	return s
}

func v2Members(t *testing.T, ids ...string) []*NodeInfo {
	var out []*NodeInfo
	for i, id := range ids {
		v, err := v2Key(t, byte(i+1)).Verifier()
		require.NoError(t, err)
		pk, err := v.MarshalPublicKey()
		require.NoError(t, err)
		out = append(out, &NodeInfo{NodeID: id, SigKey: pk, Stake: 1})
	}
	return out
}

func v2Genesis(t *testing.T) *RootTrustBaseV2 {
	return &RootTrustBaseV2{Version: 2, NetworkID: 5, Epoch: 1, EpochStart: 1, RootNodes: v2Members(t, "a", "b", "c", "d"), QuorumThreshold: 3,
		StateHash: bytes.Repeat([]byte{0x11}, 32), ChangeRecordHash: nil, PreviousEntryID: make([]byte, 32)}
}

// v2Next builds epoch e+1 (members "a".."d" again, other weights/keys are not needed) signed by the given predecessor members.
func v2Next(t *testing.T, prev *RootTrustBaseV2, signers ...string) *RootTrustBaseV2 {
	id, err := prev.EntryID()
	require.NoError(t, err)
	n := &RootTrustBaseV2{Version: 2, NetworkID: prev.NetworkID, Epoch: prev.Epoch + 1, EpochStart: prev.EpochStart + 100, RootNodes: v2Members(t, "a", "b", "c", "d"),
		QuorumThreshold: 3, StateHash: bytes.Repeat([]byte{0x22}, 32), ChangeRecordHash: bytes.Repeat([]byte{0x33}, 32), PreviousEntryID: id[:]}
	for _, s := range signers {
		require.NoError(t, n.Sign(s, v2Key(t, byte(slices.IndexFunc(prev.RootNodes, func(m *NodeInfo) bool { return m.NodeID == s })+1))))
	}
	return n
}

func TestV2VectorsAreFrozen(t *testing.T) {
	g := v2Genesis(t)
	gb, err := g.MarshalCBOR()
	require.NoError(t, err)
	gid, err := g.EntryID()
	require.NoError(t, err)
	e2 := v2Next(t, g, "a", "b", "c")
	sb, err := e2.SigBytes()
	require.NoError(t, err)
	id2, err := e2.EntryID()
	require.NoError(t, err)
	full, err := e2.MarshalCBOR()
	require.NoError(t, err)
	// frozen vectors: members "a".."d" with the keys 0x01.., 0x02.. (repeated bytes), weights 1, network 5; signatures are RFC 6979 deterministic
	require.Equal(t, "d998588a02050101848361615821031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f018361625821024d4b6cd1361032ca9bd2aeb9d900aa4d45d9ead80ac9423374c451a7254d076601836163582102531fe6068134503d2723133227c867ac8fa6c83c537e9a44c3c5bdbdcb1fe33701836164582103462779ad4aad39514614751a71085f2f10e1c7a593e4e030efb5b8721ce55b0b010358201111111111111111111111111111111111111111111111111111111111111111f658200000000000000000000000000000000000000000000000000000000000000000f6", hex.EncodeToString(gb), "genesis bytes")
	require.Equal(t, "a463562c55b380f62cb31ed2838d7640c64e07e7c383e0ca8410fc95663380d4", hex.EncodeToString(gid[:]), "genesis EntryID")
	require.Equal(t, "d998588a0205021865848361615821031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f018361625821024d4b6cd1361032ca9bd2aeb9d900aa4d45d9ead80ac9423374c451a7254d076601836163582102531fe6068134503d2723133227c867ac8fa6c83c537e9a44c3c5bdbdcb1fe33701836164582103462779ad4aad39514614751a71085f2f10e1c7a593e4e030efb5b8721ce55b0b010358202222222222222222222222222222222222222222222222222222222222222222582033333333333333333333333333333333333333333333333333333333333333335820a463562c55b380f62cb31ed2838d7640c64e07e7c383e0ca8410fc95663380d4f6", hex.EncodeToString(sb), "epoch 2 SigBytes (signature field null)")
	require.Equal(t, "5e8fe7130ebe74100595501b8e3f75483b5d6e8d97e8c12994e524719dc38ca3", hex.EncodeToString(id2[:]), "epoch 2 EntryID = SHA-256(SigBytes)")
	require.Equal(t, "d998588a0205021865848361615821031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f018361625821024d4b6cd1361032ca9bd2aeb9d900aa4d45d9ead80ac9423374c451a7254d076601836163582102531fe6068134503d2723133227c867ac8fa6c83c537e9a44c3c5bdbdcb1fe33701836164582103462779ad4aad39514614751a71085f2f10e1c7a593e4e030efb5b8721ce55b0b010358202222222222222222222222222222222222222222222222222222222222222222582033333333333333333333333333333333333333333333333333333333333333335820a463562c55b380f62cb31ed2838d7640c64e07e7c383e0ca8410fc95663380d4a361615841d87d4f583ba4d3e3e41fb760d81bc1513cd004e32f499d6f1a247cafce8fa4526ff447ce34ef53201bcd84ab70dc40fdc4eaea9cc71f7a879f2677a95c77bdec0061625841cda45e39931baf01908af605f7967b535199237b3dc25a79dccdaf3d4b048dd406fb423d653b6c7536178d8d6b13f7bf875cff15b2fd1215ef95e7cb49aba85c0161635841be0b22d8e9285758b284ca79736113cf372288eecb9eb687eb2bb4091b1462a15a28c67e58490110b03a41355b0f51f985ae6b89c9ac47cd44a2b101fa03c8b401", hex.EncodeToString(full), "epoch 2 full record with signatures a, b, c")
	require.Equal(t, byte(0xf6), sb[len(sb)-1], "the preimage carries null in the signature position")
	require.Equal(t, byte(0xf6), gb[len(gb)-1], "genesis carries null signatures")
	require.Equal(t, []byte{0xd9, 0x98, 0x58}, gb[:3], "tag 39000")
	// a reader decodes the frozen bytes and authenticates them from the genesis
	dec, err := DecodeRootTrustBaseV2(full)
	require.NoError(t, err)
	require.NoError(t, dec.VerifySuccessor(g))
}

func TestV2SignatureSubsetsGiveTheSameIdentity(t *testing.T) {
	g := v2Genesis(t)
	abc := v2Next(t, g, "a", "b", "c")
	bcd := v2Next(t, g, "b", "c", "d")
	abcd := v2Next(t, g, "a", "b", "c", "d")
	idABC, _ := abc.EntryID()
	idBCD, _ := bcd.EntryID()
	idABCD, _ := abcd.EntryID()
	require.Equal(t, idABC, idBCD)
	require.Equal(t, idABC, idABCD)
	b1, _ := abc.MarshalCBOR()
	b2, _ := bcd.MarshalCBOR()
	require.NotEqual(t, b1, b2, "the full records differ")
	for _, e := range []*RootTrustBaseV2{abc, bcd, abcd} {
		require.NoError(t, e.VerifySuccessor(g))
	}
	// the successor links to the same predecessor identity whichever subset the predecessor carried
	n3a := v2Next(t, abc, "a", "b", "c")
	n3b := v2Next(t, bcd, "a", "b", "c")
	require.Equal(t, n3a.PreviousEntryID, n3b.PreviousEntryID)
}

func TestV2RoundTripAndGenesis(t *testing.T) {
	g := v2Genesis(t)
	require.NoError(t, g.VerifyGenesis())
	b, err := g.MarshalCBOR()
	require.NoError(t, err)
	back, err := DecodeRootTrustBaseV2(b)
	require.NoError(t, err)
	require.Equal(t, g.RootNodes[0].NodeID, back.RootNodes[0].NodeID)
	require.Nil(t, back.Signatures)
	e2 := v2Next(t, g, "a", "b", "c")
	b2, _ := e2.MarshalCBOR()
	var viaMethod RootTrustBaseV2
	require.NoError(t, viaMethod.UnmarshalCBOR(b2))
	require.Equal(t, e2.Signatures, viaMethod.Signatures)
}

func TestV2AndV1AreNotInterchangeable(t *testing.T) {
	g := v2Genesis(t)
	b, _ := g.MarshalCBOR()
	var v1 RootTrustBaseV1
	require.Error(t, v1.UnmarshalCBOR(b), "a V1 reader refuses V2 bytes")
	nodes := v2Members(t, "a", "b", "c", "d")
	tb1, err := NewTrustBase(5, nodes)
	require.NoError(t, err)
	b1, err := tb1.MarshalCBOR()
	require.NoError(t, err)
	_, err = DecodeRootTrustBaseV2(b1)
	require.ErrorIs(t, err, ErrTrustBaseV2Encoding, "a V2 reader refuses V1 bytes")
}

// V1 bytes and Hash() are what they were before version 2 existed.
func TestV1BytesAndHashAreUnchanged(t *testing.T) {
	nodes := v2Members(t, "a", "b", "c", "d")
	tb, err := NewTrustBase(5, nodes, WithEpochStart(1))
	require.NoError(t, err)
	b, err := tb.MarshalCBOR()
	require.NoError(t, err)
	h, err := tb.Hash(crypto.SHA256)
	require.NoError(t, err)
	require.Equal(t, "c322b00f0028c52670fed69d23225fe50182e516059d8a3709c623b5f6c1f95b", hex.EncodeToString(h), "the same value on the fork's base commit")
	require.Equal(t, "d998588a01050101848361615821031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f018361625821024d4b6cd1361032ca9bd2aeb9d900aa4d45d9ead80ac9423374c451a7254d076601836163582102531fe6068134503d2723133227c867ac8fa6c83c537e9a44c3c5bdbdcb1fe33701836164582103462779ad4aad39514614751a71085f2f10e1c7a593e4e030efb5b8721ce55b0b0103f6f6f6a0", hex.EncodeToString(b))
}

func rawEntry(t *testing.T, mut func(fields []any) []any) []byte {
	g := v2Genesis(t)
	e := v2Next(t, g, "a", "b", "c")
	type alias RootTrustBaseV2
	b, err := Cbor.Marshal((*alias)(e))
	require.NoError(t, err)
	var fields []any
	require.NoError(t, cbor.Unmarshal(b, &fields))
	fields = mut(fields)
	enc, err := cbor.CoreDetEncOptions().EncMode()
	require.NoError(t, err)
	content, err := enc.Marshal(fields)
	require.NoError(t, err)
	out, err := enc.Marshal(cbor.RawTag{Number: UnicityTrustBaseTag, Content: content})
	require.NoError(t, err)
	return out
}

func TestV2StrictDecoder(t *testing.T) {
	g := v2Genesis(t)
	e := v2Next(t, g, "a", "b", "c")
	good, err := e.MarshalCBOR()
	require.NoError(t, err)
	_, err = DecodeRootTrustBaseV2(good)
	require.NoError(t, err)

	cases := map[string][]byte{
		"trailing byte":       append(slices.Clone(good), 0x00),
		"truncated":           good[:len(good)-1],
		"wrong tag":           append([]byte{0xd9, 0x98, 0x59}, good[3:]...),
		"untagged":            good[3:],
		"version 1":           rawEntry(t, func(f []any) []any { f[0] = uint64(1); return f }),
		"version 3":           rawEntry(t, func(f []any) []any { f[0] = uint64(3); return f }),
		"extra field":         rawEntry(t, func(f []any) []any { return append(f, uint64(7)) }),
		"missing signature":   rawEntry(t, func(f []any) []any { return f[:len(f)-1] }),
		"signatures as array": rawEntry(t, func(f []any) []any { f[len(f)-1] = []any{[]byte{1}}; return f }),
	}
	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := DecodeRootTrustBaseV2(in)
			require.ErrorIs(t, err, ErrTrustBaseV2Encoding)
		})
	}

	// duplicate signature-map key: hand-built, since a Go map cannot hold two
	t.Run("duplicate map key", func(t *testing.T) {
		e1 := v2Next(t, g, "a")
		sig := e1.Signatures["a"]
		var dup bytes.Buffer
		dup.Write([]byte{0xa2}) // map(2)
		for i := 0; i < 2; i++ {
			dup.Write([]byte{0x61, 'a', 0x58, byte(len(sig))})
			dup.Write(sig)
		}
		raw := e1
		b, _ := raw.MarshalCBOR()
		single := []byte{0xa1, 0x61, 'a', 0x58, byte(len(sig))}
		single = append(single, sig...)
		i := bytes.LastIndex(b, single)
		require.Positive(t, i)
		forged := append(slices.Clone(b[:i]), dup.Bytes()...)
		forged = append(forged, b[i+len(single):]...)
		_, err := DecodeRootTrustBaseV2(forged)
		require.ErrorIs(t, err, ErrTrustBaseV2Encoding)
		require.Contains(t, err.Error(), "duplicate")
	})

	t.Run("non-deterministic encoding of the same value", func(t *testing.T) {
		// epoch 2 written as a 2-byte uint instead of the shortest form
		i := bytes.Index(good, []byte{0x02, 0x18, 0x65}) // epoch=2, epochStart=101
		require.Positive(t, i)
		long := append(slices.Clone(good[:i]), 0x18, 0x02)
		long = append(long, good[i+1:]...)
		_, err := DecodeRootTrustBaseV2(long)
		require.ErrorIs(t, err, ErrTrustBaseV2Encoding)
	})

	t.Run("indefinite length", func(t *testing.T) {
		raw := rawEntry(t, func(f []any) []any { return f })
		// array(10) -> indefinite array
		i := bytes.Index(raw, []byte{0x8a})
		require.Positive(t, i)
		ind := append(slices.Clone(raw[:i]), 0x9f)
		ind = append(ind, raw[i+1:]...)
		ind = append(ind, 0xff)
		_, err := DecodeRootTrustBaseV2(ind)
		require.ErrorIs(t, err, ErrTrustBaseV2Encoding)
	})

	t.Run("oversize member list is refused before allocation", func(t *testing.T) {
		raw := rawEntry(t, func(f []any) []any {
			members := make([]any, MaxTrustBaseV2Members+100)
			for i := range members {
				members[i] = []any{fmt.Sprintf("n%04d", i), []byte{2}, uint64(1)}
			}
			f[4] = members
			return f
		})
		_, err := DecodeRootTrustBaseV2(raw)
		require.ErrorIs(t, err, ErrTrustBaseV2Encoding)
	})
}

func TestV2StructureRules(t *testing.T) {
	mk := func(mut func(e *RootTrustBaseV2)) error {
		g := v2Genesis(t)
		e := v2Next(t, g, "a", "b", "c")
		mut(e)
		return e.Validate()
	}
	require.NoError(t, mk(func(*RootTrustBaseV2) {}))
	cases := map[string]func(e *RootTrustBaseV2){
		"epoch zero":        func(e *RootTrustBaseV2) { e.Epoch = 0 },
		"network id zero":   func(e *RootTrustBaseV2) { e.NetworkID = 0 },
		"no members":        func(e *RootTrustBaseV2) { e.RootNodes = nil },
		"unsorted members":  func(e *RootTrustBaseV2) { e.RootNodes[0], e.RootNodes[1] = e.RootNodes[1], e.RootNodes[0] },
		"duplicate member":  func(e *RootTrustBaseV2) { e.RootNodes[1].NodeID = "a" },
		"empty node id":     func(e *RootTrustBaseV2) { e.RootNodes[0].NodeID = "" },
		"non-UTF-8 node id": func(e *RootTrustBaseV2) { e.RootNodes[3].NodeID = "d\xff" },
		"long node id": func(e *RootTrustBaseV2) {
			e.RootNodes[3].NodeID = string(bytes.Repeat([]byte{'z'}, MaxTrustBaseV2NodeIDLen+1))
		},
		"shared signing key":     func(e *RootTrustBaseV2) { e.RootNodes[1].SigKey = slices.Clone(e.RootNodes[0].SigKey) },
		"zero weight":            func(e *RootTrustBaseV2) { e.RootNodes[0].Stake = 0 },
		"huge weight":            func(e *RootTrustBaseV2) { e.RootNodes[0].Stake = MaxTrustBaseV2Weight + 1 },
		"uncompressed key":       func(e *RootTrustBaseV2) { e.RootNodes[0].SigKey = append([]byte{4}, e.RootNodes[0].SigKey[1:]...) },
		"short key":              func(e *RootTrustBaseV2) { e.RootNodes[0].SigKey = e.RootNodes[0].SigKey[:32] },
		"threshold too low":      func(e *RootTrustBaseV2) { e.QuorumThreshold = 2 },
		"threshold too high":     func(e *RootTrustBaseV2) { e.QuorumThreshold = 4 },
		"state hash length":      func(e *RootTrustBaseV2) { e.StateHash = []byte{1} },
		"change hash length":     func(e *RootTrustBaseV2) { e.ChangeRecordHash = make([]byte, 33) },
		"predecessor length":     func(e *RootTrustBaseV2) { e.PreviousEntryID = make([]byte, 31) },
		"non-genesis unsigned":   func(e *RootTrustBaseV2) { e.Signatures = nil },
		"non-genesis empty sigs": func(e *RootTrustBaseV2) { e.Signatures = map[string]abhex.Bytes{} },
		"genesis with signatures": func(e *RootTrustBaseV2) {
			e.PreviousEntryID = make([]byte, 32)
		},
	}
	for name, mut := range cases {
		t.Run(name, func(t *testing.T) { require.ErrorIs(t, mk(mut), ErrTrustBaseV2Invalid) })
	}
	t.Run("weighted threshold", func(t *testing.T) {
		e := v2Genesis(t)
		e.RootNodes[0].Stake, e.RootNodes[1].Stake = 5, 3 // W = 10
		e.QuorumThreshold = 7
		require.NoError(t, e.Validate())
		e.QuorumThreshold = 6
		require.ErrorIs(t, e.Validate(), ErrTrustBaseV2Invalid)
	})
	t.Run("maximum committee total cannot overflow", func(t *testing.T) {
		e := v2Genesis(t)
		e.RootNodes = nil
		for i := 0; i < MaxTrustBaseV2Members; i++ {
			sg, err := abcrypto.NewInMemorySecp256K1Signer()
			require.NoError(t, err)
			vf, _ := sg.Verifier()
			pk, _ := vf.MarshalPublicKey()
			m := &NodeInfo{SigKey: pk}
			m.NodeID = fmt.Sprintf("n%04d", i)
			m.Stake = MaxTrustBaseV2Weight
			e.RootNodes = append(e.RootNodes, m)
		}
		total := uint64(MaxTrustBaseV2Members) * MaxTrustBaseV2Weight
		e.QuorumThreshold = total*2/3 + 1
		require.NoError(t, e.Validate())
	})
}

func TestV2StrictSignatureVerification(t *testing.T) {
	g := v2Genesis(t)
	good := v2Next(t, g, "a", "b", "c")
	require.NoError(t, good.VerifySuccessor(g))
	sb, _ := good.SigBytes()

	flip := func(sig []byte) []byte { s := slices.Clone(sig); s[3] ^= 1; return s }
	with := func(mut func(e *RootTrustBaseV2)) error {
		e := v2Next(t, g, "a", "b", "c")
		mut(e)
		return e.VerifySuccessor(g)
	}
	t.Run("an invalid extra fails although the others reach quorum", func(t *testing.T) {
		err := with(func(e *RootTrustBaseV2) { e.Signatures["d"] = flip(e.Signatures["a"]) })
		require.ErrorIs(t, err, ErrTrustBaseV2Signature)
	})
	t.Run("an unknown signer fails although the others reach quorum", func(t *testing.T) {
		err := with(func(e *RootTrustBaseV2) { e.Signatures["z"] = e.Signatures["a"] })
		require.ErrorIs(t, err, ErrTrustBaseV2Signature)
		require.Contains(t, err.Error(), "not a member")
	})
	t.Run("a signature bound to the wrong member fails", func(t *testing.T) {
		err := with(func(e *RootTrustBaseV2) { e.Signatures["d"] = e.Signatures["a"] })
		require.ErrorIs(t, err, ErrTrustBaseV2Signature)
	})
	t.Run("below quorum", func(t *testing.T) {
		e := v2Next(t, g, "a", "b")
		require.ErrorIs(t, e.VerifySuccessor(g), ErrTrustBaseV2Signature)
	})
	t.Run("signature forms", func(t *testing.T) {
		sig := good.Signatures["a"]
		require.Len(t, sig, 65)
		for name, s := range map[string][]byte{"63 bytes": sig[:63], "66 bytes": append(slices.Clone(sig), 0), "recovery id 2": append(slices.Clone(sig[:64]), 2), "empty": {}} {
			t.Run(name, func(t *testing.T) {
				err := with(func(e *RootTrustBaseV2) { e.Signatures["a"] = s })
				require.ErrorIs(t, err, ErrTrustBaseV2Signature)
			})
		}
		// V2 entries take the strict recoverable rule only: the 64-byte compact form is rejected
		require.ErrorIs(t, with(func(e *RootTrustBaseV2) { e.Signatures["a"] = sig[:64] }), ErrTrustBaseV2Signature, "the 64-byte compact form is not a V2 form")
		// the 65-byte form must carry the recovery id that recovers to the member's key
		err := with(func(e *RootTrustBaseV2) { e.Signatures["a"] = append(slices.Clone(sig[:64]), sig[64]^1) })
		require.ErrorIs(t, err, ErrTrustBaseV2Signature, "the other recovery id value recovers to another key")
		require.NoError(t, with(func(e *RootTrustBaseV2) { e.Signatures["a"] = slices.Clone(sig) }))
	})
	t.Run("a signature over other bytes", func(t *testing.T) {
		err := g.VerifyQuorumSignatures(append(slices.Clone(sb), 0), good.Signatures)
		require.ErrorIs(t, err, ErrTrustBaseV2Signature)
	})
	t.Run("the current members' signatures do not count, only the predecessor's", func(t *testing.T) {
		g2 := v2Genesis(t)
		g2.RootNodes = v2Members(t, "a", "b", "c", "d")
		// signed by keys 5..8, which are not the predecessor's members' keys under these ids
		e := v2Next(t, g2)
		for i, id := range []string{"a", "b", "c"} {
			require.NoError(t, e.Sign(id, v2Key(t, byte(5+i))))
		}
		require.ErrorIs(t, e.VerifySuccessor(g2), ErrTrustBaseV2Signature)
	})
}

func TestV2ChainRules(t *testing.T) {
	g := v2Genesis(t)
	ok := func(mut func(e *RootTrustBaseV2)) error {
		e := v2Next(t, g)
		mut(e)
		// re-sign after the mutation so only the chain rule can fail
		e.Signatures = nil
		for i, id := range []string{"a", "b", "c"} {
			require.NoError(t, e.Sign(id, v2Key(t, byte(i+1))))
		}
		return e.VerifySuccessor(g)
	}
	require.NoError(t, ok(func(*RootTrustBaseV2) {}))
	cases := map[string]func(e *RootTrustBaseV2){
		"other network":     func(e *RootTrustBaseV2) { e.NetworkID = 6 },
		"epoch skipped":     func(e *RootTrustBaseV2) { e.Epoch = 3 },
		"epoch repeated":    func(e *RootTrustBaseV2) { e.Epoch = 1 },
		"start not later":   func(e *RootTrustBaseV2) { e.EpochStart = g.EpochStart },
		"wrong predecessor": func(e *RootTrustBaseV2) { e.PreviousEntryID = bytes.Repeat([]byte{9}, 32) },
	}
	for name, mut := range cases {
		t.Run(name, func(t *testing.T) { require.ErrorIs(t, ok(mut), ErrTrustBaseV2Chain) })
	}
	t.Run("genesis is not a successor", func(t *testing.T) { require.ErrorIs(t, g.VerifySuccessor(g), ErrTrustBaseV2Chain) })
	t.Run("no predecessor", func(t *testing.T) {
		require.ErrorIs(t, v2Next(t, g, "a", "b", "c").VerifySuccessor(nil), ErrTrustBaseV2Chain)
	})
	t.Run("a non-genesis entry is not a genesis", func(t *testing.T) {
		require.ErrorIs(t, v2Next(t, g, "a", "b", "c").VerifyGenesis(), ErrTrustBaseV2Invalid)
	})
	t.Run("the predecessor link is the unsigned identity, not a hash with signatures", func(t *testing.T) {
		abc := v2Next(t, g, "a", "b", "c")
		h, err := abc.EntryID()
		require.NoError(t, err)
		full, _ := abc.MarshalCBOR()
		require.NotEqual(t, h[:], sha256Of(full))
	})
}

func sha256Of(b []byte) []byte { h := crypto.SHA256.New(); h.Write(b); return h.Sum(nil) }

// An absent hash has one byte form: null. The empty byte string is refused on decode and an in-memory empty value encodes as null, so one entry has one
// EntryID.
func TestV2AbsentHashesAreCanonicalNull(t *testing.T) {
	g := v2Genesis(t)
	absent := func(mut func(e *RootTrustBaseV2)) *RootTrustBaseV2 {
		e := *g
		mut(&e)
		return &e
	}
	nilForm := absent(func(e *RootTrustBaseV2) { e.StateHash, e.ChangeRecordHash = nil, nil })
	emptyForm := absent(func(e *RootTrustBaseV2) { e.StateHash, e.ChangeRecordHash = []byte{}, []byte{} })

	t.Run("an in-memory empty value encodes as null and has the same identity", func(t *testing.T) {
		a, err := nilForm.MarshalCBOR()
		require.NoError(t, err)
		b, err := emptyForm.MarshalCBOR()
		require.NoError(t, err)
		require.Equal(t, a, b)
		ia, err := nilForm.EntryID()
		require.NoError(t, err)
		ib, err := emptyForm.EntryID()
		require.NoError(t, err)
		require.Equal(t, ia, ib)
		_, err = DecodeRootTrustBaseV2(b)
		require.NoError(t, err)
	})
	t.Run("the empty byte string form is refused on decode", func(t *testing.T) {
		raw, err := nilForm.MarshalCBOR()
		require.NoError(t, err)
		// hand-built second byte form: the two null hash fields (f6 f6) replaced by two empty byte strings (40 40), just before the 32-byte previous entry id
		marker := append([]byte{0xf6, 0xf6, 0x58, 0x20}, make([]byte, 32)...)
		i := bytes.LastIndex(raw, marker)
		require.GreaterOrEqual(t, i, 0, "the null hash fields are where the test expects them")
		other := slices.Concat(raw[:i], []byte{0x40, 0x40}, raw[i+2:])
		_, err = DecodeRootTrustBaseV2(other)
		require.ErrorIs(t, err, ErrTrustBaseV2Encoding)
		require.Contains(t, err.Error(), "empty byte string")
		// each field on its own
		for _, one := range [][]byte{{0x40, 0xf6}, {0xf6, 0x40}} {
			o := slices.Concat(raw[:i], one, raw[i+2:])
			_, err = DecodeRootTrustBaseV2(o)
			require.ErrorIs(t, err, ErrTrustBaseV2Encoding)
		}
	})
	t.Run("a present hash is exactly 32 bytes", func(t *testing.T) {
		for _, n := range []int{1, 31, 33} {
			e := absent(func(e *RootTrustBaseV2) { e.StateHash = bytes.Repeat([]byte{7}, n) })
			require.ErrorIs(t, e.Validate(), ErrTrustBaseV2Invalid, "%d bytes", n)
		}
		e := absent(func(e *RootTrustBaseV2) {
			e.StateHash, e.ChangeRecordHash = bytes.Repeat([]byte{7}, 32), bytes.Repeat([]byte{8}, 32)
		})
		raw, err := e.MarshalCBOR()
		require.NoError(t, err)
		back, err := DecodeRootTrustBaseV2(raw)
		require.NoError(t, err)
		require.Equal(t, e.StateHash, back.StateHash)
	})
}
