package types

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"math/big"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"

	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	secp256k1lib "github.com/ethereum/go-ethereum/crypto/secp256k1"
	abcrypto "github.com/unicitynetwork/bft-go-base/crypto"
)

// Shared signature-recovery regression fixtures (O3): the canonical rule is a 65-byte r||s||v signature, low-S,
// v in 0..3, and the key recovered with v must equal the trusted key. The JSON is meant to be consumed by the
// Rust and JS verifiers as well. Regenerate with: go test ./types -run TestSignatureRecoveryFixtures -update-sigfixtures

var updateSigFixtures = flag.Bool("update-sigfixtures", false, "rewrite testdata/signature-recovery/v1/vectors.json")

const sigFixturePath = "../testdata/signature-recovery/v1/vectors.json"

var secpN, _ = new(big.Int).SetString("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", 16)

type sigVector struct {
	Name   string `json:"name"`
	Sig    string `json:"signature"`
	Accept bool   `json:"accept"`
	Note   string `json:"note,omitempty"`
}

type primitiveFixture struct {
	PublicKey string      `json:"publicKeyCompressed"`
	Hash      string      `json:"messageHashSha256"`
	Message   string      `json:"messageUtf8"`
	Vectors   []sigVector `json:"vectors"`
}

type sealCase struct {
	Name   string `json:"name"`
	Seal   string `json:"sealCbor"`
	Accept bool   `json:"accept"`
	Note   string `json:"note,omitempty"`
}

type sealFixture struct {
	Description string     `json:"description"`
	NetworkID   uint16     `json:"networkId"`
	Epoch       uint64     `json:"epoch"`
	Quorum      uint64     `json:"quorumThreshold"`
	Nodes       []nodeFx   `json:"nodes"`
	TrustBase   string     `json:"trustBaseCbor"`
	Cases       []sealCase `json:"cases"`
}

type nodeFx struct {
	ID        string `json:"id"`
	PublicKey string `json:"publicKeyCompressed"`
	Stake     uint64 `json:"stake"`
}

// recoveryVector carries its own key and digest: primitive inputs with constructed expected keys.
type recoveryVector struct {
	Name      string `json:"name"`
	PublicKey string `json:"publicKeyCompressed"`
	Hash      string `json:"digest"`
	Sig       string `json:"signature"`
	Accept    bool   `json:"accept"`
	Note      string `json:"note,omitempty"`
}

type sigFixtureFile struct {
	Spec      []string         `json:"spec"`
	Primitive primitiveFixture `json:"primitive"`
	Recovery  []recoveryVector `json:"recovery"`
	Seal      sealFixture      `json:"seal"`
}

func fixedSigner(t *testing.T, n int) abcrypto.Signer {
	sk := sha256.Sum256([]byte("unicity-o3-fixture-key-" + strconv.Itoa(n))) // public deterministic test keys
	s, err := abcrypto.NewInMemorySecp256K1SignerFromKey(sk[:])
	require.NoError(t, err)
	return s
}

func withV(sig []byte, v byte) []byte { c := bytes.Clone(sig); c[64] = v; return c }

// highS returns the same (r, n-s) with the flipped parity: a mathematically valid but non-canonical signature.
func highS(sig []byte) []byte {
	s := new(big.Int).SetBytes(sig[32:64])
	s.Sub(secpN, s)
	c := bytes.Clone(sig)
	copy(c[32:64], make([]byte, 32))
	s.FillBytes(c[32:64])
	c[64] ^= 1
	return c
}

var secpP, _ = new(big.Int).SetString("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f", 16)

// refRecover is the TEST-ONLY independent reference of the owner-approved formulation
// Q' = a*R + b*G, a = s/r, b = -z/r (mod n), x = r + (v>>1)*n, R = lift(x, v&1). It returns nil if any
// step is rejected (x >= p, no square root, identity). Production code does not contain it.
func refRecover(hash []byte, sig []byte) *btcPoint {
	c := ethcrypto.S256()
	r, s := new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:64])
	v := sig[64]
	if r.Sign() == 0 || r.Cmp(secpN) >= 0 || s.Sign() == 0 || s.Cmp(secpN) >= 0 || v > 3 {
		return nil
	}
	x := new(big.Int).Set(r)
	if v&2 != 0 {
		x.Add(x, secpN)
	}
	if x.Cmp(secpP) >= 0 {
		return nil
	}
	y2 := new(big.Int).Exp(x, big.NewInt(3), secpP)
	y2.Add(y2, big.NewInt(7)).Mod(y2, secpP)
	y := new(big.Int).ModSqrt(y2, secpP)
	if y == nil {
		return nil
	}
	if y.Bit(0) != uint(v&1) {
		y.Sub(secpP, y)
	}
	z := new(big.Int).Mod(new(big.Int).SetBytes(hash), secpN)
	rinv := new(big.Int).ModInverse(r, secpN)
	a := new(big.Int).Mul(s, rinv)
	a.Mod(a, secpN)
	b := new(big.Int).Mul(z, rinv)
	b.Neg(b).Mod(b, secpN)
	ax, ay := c.ScalarMult(x, y, a.Bytes())
	var qx, qy *big.Int
	if b.Sign() == 0 {
		qx, qy = ax, ay
	} else {
		gx, gy := c.ScalarBaseMult(b.Bytes())
		if ax.Sign() == 0 && ay.Sign() == 0 {
			qx, qy = gx, gy
		} else {
			qx, qy = c.Add(ax, ay, gx, gy)
		}
	}
	if qx.Sign() == 0 && qy.Sign() == 0 {
		return nil // identity
	}
	return &btcPoint{qx, qy}
}

type btcPoint struct{ x, y *big.Int }

func (p *btcPoint) compressed() []byte { return secp256k1lib.CompressPubkey(p.x, p.y) }

func be32(i *big.Int) []byte { return i.FillBytes(make([]byte, 32)) }

func buildRecoveryVectors(t *testing.T) []recoveryVector {
	var out []recoveryVector
	hashZero := make([]byte, 32)
	mk := func(r, s *big.Int, v byte) []byte { return append(append(be32(r), be32(s)...), v) }
	// vector computes the expectation with the independent reference (trusted key = given) AND the production verifier
	add := func(name, note string, pub []byte, hash, sig []byte, wantAccept bool) {
		ver, err := abcrypto.NewVerifierSecp256k1(pub)
		require.NoError(t, err, name)
		got := ver.VerifyHash(sig, hash) == nil
		require.Equal(t, wantAccept, got, name)
		if q := refRecover(hash, sig); wantAccept {
			require.NotNil(t, q, name)
			require.Equal(t, pub, q.compressed(), name)
		}
		out = append(out, recoveryVector{Name: name, PublicKey: hex.EncodeToString(pub), Hash: hex.EncodeToString(hash), Sig: hex.EncodeToString(sig), Accept: got, Note: note})
	}
	// positive v=2 and v=3 (primitive inputs r=2, s=1, z=0): the trusted key is the reference's recovered key
	r2, one := big.NewInt(2), big.NewInt(1)
	q2 := refRecover(hashZero, mk(r2, one, 2))
	q3 := refRecover(hashZero, mk(r2, one, 3))
	require.NotNil(t, q2)
	require.NotNil(t, q3)
	require.Equal(t, q2.x, q3.x)
	add("v2-recovers-trusted-key", "r=2,s=1,z=0: x=r+n lifts to a curve point; valid ID 2 must be accepted", q2.compressed(), hashZero, mk(r2, one, 2), true)
	add("v3-recovers-trusted-key", "same x, odd y", q3.compressed(), hashZero, mk(r2, one, 3), true)
	add("v2-signature-against-v3-key", "wrong branch", q3.compressed(), hashZero, mk(r2, one, 2), false)
	add("v3-signature-against-v2-key", "wrong branch", q2.compressed(), hashZero, mk(r2, one, 3), false)
	add("v0-for-v2-signature", "same r,s, no overflow lift: recovers another key", q2.compressed(), hashZero, mk(r2, one, 0), false)
	// r + n == p and overflow (v>=2): x >= p, no lift
	pn := new(big.Int).Sub(secpP, secpN)
	add("r-plus-n-equals-p-v2", "x = p is not a field element", q2.compressed(), hashZero, mk(pn, one, 2), false)
	add("r-plus-n-equals-p-v3", "", q2.compressed(), hashZero, mk(pn, one, 3), false)
	add("r-plus-n-overflow-v2", "r+n > p", q2.compressed(), hashZero, mk(new(big.Int).Add(pn, big.NewInt(5)), one, 2), false)
	add("r-near-n-overflow-v3", "r = n-1, x = r+n >> p", q2.compressed(), hashZero, mk(new(big.Int).Sub(secpN, one), one, 3), false)
	// decompression failure: smallest r whose x has no square root for y^2 = x^3+7
	for r := int64(1); ; r++ {
		y2 := new(big.Int).Exp(big.NewInt(r), big.NewInt(3), secpP)
		y2.Add(y2, big.NewInt(7)).Mod(y2, secpP)
		if new(big.Int).ModSqrt(y2, secpP) == nil {
			add("decompression-failure-v0", "x="+strconv.FormatInt(r, 10)+" is not on the curve", q2.compressed(), hashZero, mk(big.NewInt(r), one, 0), false)
			add("decompression-failure-v1", "", q2.compressed(), hashZero, mk(big.NewInt(r), one, 1), false)
			break
		}
	}
	// recovered identity: R = G (r = Gx, v = parity of Gy), s = 1, z = 1 gives s*R = z*G, Q' = identity
	gx, gy := ethcrypto.S256().Params().Gx, ethcrypto.S256().Params().Gy
	digestOne := be32(one)
	idSig := mk(gx, one, byte(gy.Bit(0)))
	require.Nil(t, refRecover(digestOne, idSig), "reference: identity")
	add("recovered-identity", "R=G, s=z=1: Q' is the point at infinity", q2.compressed(), digestOne, idSig, false)

	// digests: zero, all-ones (>= n), exactly n, n+1 are reduced mod n; real signatures by a fixed key
	signer := fixedSigner(t, 99)
	ver, _ := signer.Verifier()
	pub, _ := ver.MarshalPublicKey()
	hn := be32(secpN)
	hn1 := be32(new(big.Int).Add(secpN, one))
	hff := bytes.Repeat([]byte{0xff}, 32)
	sign := func(h []byte) []byte {
		sg, err := signer.SignHash(h)
		require.NoError(t, err)
		return sg
	}
	add("zero-digest", "digest 0 is a valid message representative", pub, hashZero, sign(hashZero), true)
	add("digest-all-ones-ge-n", "digest >= n is reduced mod n", pub, hff, sign(hff), true)
	add("digest-equals-n", "z = 0 after reduction", pub, hn, sign(hn), true)
	add("signature-of-zero-digest-for-digest-n", "n reduces to the zero digest: the same signature verifies", pub, hn, sign(hashZero), true)
	add("signature-of-digest-1-for-digest-n-plus-1", "n+1 reduces to 1", pub, hn1, sign(be32(one)), true)
	add("signature-of-zero-digest-for-digest-1", "different representative", pub, be32(one), sign(hashZero), false)
	return out
}

func buildSigFixtures(t *testing.T) sigFixtureFile {
	signer := fixedSigner(t, 0)
	ver, err := signer.Verifier()
	require.NoError(t, err)
	pub, err := ver.MarshalPublicKey()
	require.NoError(t, err)
	msg := []byte("unicity o3 recovery fixture")
	h := sha256.Sum256(msg)
	sig, err := signer.SignBytes(msg)
	require.NoError(t, err)
	require.Len(t, sig, 65)
	require.LessOrEqual(t, sig[64], byte(1))

	vec := func(name string, s []byte, note string) sigVector {
		accept := ver.VerifyHash(s, h[:]) == nil
		return sigVector{Name: name, Sig: hex.EncodeToString(s), Accept: accept, Note: note}
	}
	zero := make([]byte, 32)
	var vs []sigVector
	vs = append(vs, vec("valid", sig, "r||s||v as produced by the signer"))
	for _, v := range []byte{0, 1, 2, 3, 4, 27, 28, 31, 255} {
		if v == sig[64] {
			continue
		}
		vs = append(vs, vec("recovery-id-"+strconv.Itoa(int(v)), withV(sig, v), "same r,s; only v changed"))
	}
	vs = append(vs, vec("recovery-id-xor-1", withV(sig, sig[64]^1), "stays in range but recovers another key"))
	vs = append(vs, vec("high-s-flipped-parity", highS(sig), "(r, n-s, v^1): valid ECDSA, non-canonical"))
	vs = append(vs, vec("high-s-same-v", withV(highS(sig), sig[64]), ""))
	vs = append(vs, vec("compact-64", sig[:64], "no recovery id: not a canonical seal signature"))
	vs = append(vs, vec("truncated-63", sig[:63], ""))
	vs = append(vs, vec("extended-66", append(bytes.Clone(sig), 0), ""))
	vs = append(vs, vec("empty", []byte{}, ""))
	r0 := bytes.Clone(sig)
	copy(r0[:32], zero)
	vs = append(vs, vec("r-zero", r0, ""))
	s0 := bytes.Clone(sig)
	copy(s0[32:64], zero)
	vs = append(vs, vec("s-zero", s0, ""))
	sn := bytes.Clone(sig)
	secpN.FillBytes(sn[32:64])
	vs = append(vs, vec("s-equals-n", sn, ""))
	rn := bytes.Clone(sig)
	secpN.FillBytes(rn[:32])
	vs = append(vs, vec("r-equals-n", rn, ""))
	for _, v := range vs {
		if v.Name == "valid" {
			require.True(t, v.Accept)
		} else if v.Accept {
			t.Fatalf("vector %s unexpectedly accepted", v.Name)
		}
	}

	// seal level: 4 admitted nodes, quorum 3
	var nodes []*NodeInfo
	var fxNodes []nodeFx
	signers := map[string]abcrypto.Signer{}
	for i := 1; i <= 4; i++ {
		id := "node" + strconv.Itoa(i)
		s := fixedSigner(t, i)
		v, err := s.Verifier()
		require.NoError(t, err)
		pk, err := v.MarshalPublicKey()
		require.NoError(t, err)
		nodes = append(nodes, &NodeInfo{NodeID: id, SigKey: pk, Stake: 1})
		fxNodes = append(fxNodes, nodeFx{ID: id, PublicKey: hex.EncodeToString(pk), Stake: 1})
		signers[id] = s
	}
	tb, err := NewTrustBase(NetworkLocal, nodes, WithEpoch(1))
	require.NoError(t, err)
	tbBytes, err := tb.MarshalCBOR()
	require.NoError(t, err)
	seal := func(mutate func(m SignatureMap)) *UnicitySeal {
		sl := &UnicitySeal{Version: 1, NetworkID: NetworkLocal, RootChainRoundNumber: 7, Epoch: 1, Timestamp: GenesisTime + 1,
			PreviousHash: bytes.Repeat([]byte{1}, 32), Hash: bytes.Repeat([]byte{2}, 32)}
		for id, s := range signers {
			require.NoError(t, sl.Sign(id, s))
		}
		if mutate != nil {
			mutate(sl.Signatures)
		}
		return sl
	}
	flip := func(id string) func(SignatureMap) {
		return func(m SignatureMap) { m[id] = withV(m[id], m[id][64]^1) }
	}
	var cases []sealCase
	add := func(name, note string, sl *UnicitySeal) {
		b, err := sl.MarshalCBOR()
		require.NoError(t, err)
		cases = append(cases, sealCase{Name: name, Seal: hex.EncodeToString(b), Accept: sl.Verify(tb) == nil, Note: note})
	}
	add("valid-all-four", "", seal(nil))
	add("one-v-flipped-quorum-still-met", "bad recovery id contributes zero votes; surplus invalid signature tolerated", seal(flip("node1")))
	add("two-v-flipped-quorum-lost", "only 2 valid votes of 3 needed", seal(func(m SignatureMap) { flip("node1")(m); flip("node2")(m) }))
	add("one-signature-dropped-quorum-met", "", seal(func(m SignatureMap) { delete(m, "node4") }))
	add("one-dropped-one-v-flipped-quorum-lost", "", seal(func(m SignatureMap) { delete(m, "node4"); flip("node1")(m) }))
	add("one-v-out-of-range-quorum-met", "v=4 is rejected, three valid signatures remain", seal(func(m SignatureMap) { m["node1"] = withV(m["node1"], 4) }))
	add("two-high-s-quorum-lost", "", seal(func(m SignatureMap) { m["node1"] = highS(m["node1"]); m["node2"] = highS(m["node2"]) }))
	add("surplus-compact-quorum-met", "a surplus 64-byte compact entry contributes zero votes next to a met quorum", seal(func(m SignatureMap) { m["node4"] = m["node4"][:64] }))
	add("two-compact-quorum-lost", "", seal(func(m SignatureMap) { m["node1"] = m["node1"][:64]; m["node2"] = m["node2"][:64] }))
	add("copied-signature-under-other-id-quorum-lost", "node2/node3 carry node1's signature", seal(func(m SignatureMap) { m["node2"] = m["node1"]; m["node3"] = m["node1"] }))
	for _, c := range cases {
		switch c.Name {
		case "valid-all-four", "one-v-flipped-quorum-still-met", "one-signature-dropped-quorum-met", "one-v-out-of-range-quorum-met", "surplus-compact-quorum-met":
			require.True(t, c.Accept, c.Name)
		default:
			require.False(t, c.Accept, c.Name)
		}
	}

	return sigFixtureFile{
		Spec: []string{
			"Each signature counted toward a unicity seal quorum is exactly 65 bytes r[32]||s[32]||v[1] over SHA-256 of the seal's signature-free CBOR.",
			"1 <= r,s < n; low-S (s <= n/2); v in 0..3 (no 27/28, no EIP-155).",
			"One recover-and-compare: Q' = r^-1(sR - zG) with x = r + (v>>1)*n (x < p required), R = lift(x, parity v&1), z = digest mod n (digests 0 and >= n allowed); reject on failed lift/identity. No separate ECDSA verification.",
			"The public key recovered from (hash, r, s, v) must equal the trusted key of the claimed node ID; a range check on v is not enough.",
			"A signature that does not conform contributes zero votes. The seal is accepted iff the stake of conforming signatures from distinct admitted node IDs reaches the quorum threshold.",
			"64-byte compact r||s signatures are not canonical seal signatures.",
		},
		Recovery:  buildRecoveryVectors(t),
		Primitive: primitiveFixture{PublicKey: hex.EncodeToString(pub), Hash: hex.EncodeToString(h[:]), Message: string(msg), Vectors: vs},
		Seal: sealFixture{Description: "4 nodes, stake 1 each, quorum 3, network local, epoch 1", NetworkID: uint16(NetworkLocal), Epoch: 1,
			Quorum: tb.QuorumThreshold, Nodes: fxNodes, TrustBase: hex.EncodeToString(tbBytes), Cases: cases},
	}
}

func TestSignatureRecoveryFixtures(t *testing.T) {
	got, err := json.MarshalIndent(buildSigFixtures(t), "", "  ")
	require.NoError(t, err)
	got = append(got, '\n')
	if *updateSigFixtures {
		require.NoError(t, os.MkdirAll(filepath.Dir(sigFixturePath), 0o755))
		require.NoError(t, os.WriteFile(sigFixturePath, got, 0o644))
	}
	want, err := os.ReadFile(sigFixturePath)
	require.NoError(t, err, "regenerate with -update-sigfixtures")
	require.Equal(t, string(want), string(got), "fixtures are stale; regenerate with -update-sigfixtures")
}

// The committed JSON (what Rust/JS consume) is replayed against the Go verifiers.
func TestSignatureRecoveryFixturesReplay(t *testing.T) {
	raw, err := os.ReadFile(sigFixturePath)
	require.NoError(t, err)
	var f sigFixtureFile
	require.NoError(t, json.Unmarshal(raw, &f))

	pub, _ := hex.DecodeString(f.Primitive.PublicKey)
	hash, _ := hex.DecodeString(f.Primitive.Hash)
	ver, err := abcrypto.NewVerifierSecp256k1(pub)
	require.NoError(t, err)
	for _, v := range f.Primitive.Vectors {
		sig, _ := hex.DecodeString(v.Sig)
		require.Equal(t, v.Accept, ver.VerifyHash(sig, hash) == nil, v.Name)
		require.Equal(t, v.Accept, ver.VerifyBytes(sig, []byte(f.Primitive.Message)) == nil, v.Name)
	}
	for _, v := range f.Recovery {
		pk, _ := hex.DecodeString(v.PublicKey)
		d, _ := hex.DecodeString(v.Hash)
		sg, _ := hex.DecodeString(v.Sig)
		vr, err := abcrypto.NewVerifierSecp256k1(pk)
		require.NoError(t, err, v.Name)
		require.Equal(t, v.Accept, vr.VerifyHash(sg, d) == nil, v.Name)
	}
	// the compact primitive is a separate contract
	valid, _ := hex.DecodeString(f.Primitive.Vectors[0].Sig)
	require.NoError(t, ver.(abcrypto.CompactVerifier).VerifyCompactHash(valid[:64], hash))
	require.Error(t, ver.(abcrypto.CompactVerifier).VerifyCompactHash(valid, hash))

	tbRaw, _ := hex.DecodeString(f.Seal.TrustBase)
	tb := NewRootTrustBaseV1()
	require.NoError(t, Cbor.Unmarshal(tbRaw, tb))
	for _, c := range f.Seal.Cases {
		raw, _ := hex.DecodeString(c.Seal)
		var s UnicitySeal
		require.NoError(t, Cbor.Unmarshal(raw, &s), c.Name)
		require.Equal(t, c.Accept, s.Verify(tb) == nil, c.Name)
		require.Equal(t, c.Accept, TrustBaseSealVerifier(tb).VerifySeal(&s) == nil, c.Name)
	}
}

// Differential check of the production verifier against the independent reference over random valid signatures
// and mutated variants (all v, high-S, random scalars): verdict == low-S && reference recovers the trusted key.
func TestVerifyHashMatchesTheReference(t *testing.T) {
	halfN := new(big.Int).Rsh(secpN, 1)
	for i := 0; i < 40; i++ {
		signer := fixedSigner(t, 1000+i)
		ver, _ := signer.Verifier()
		pub, _ := ver.MarshalPublicKey()
		h := sha256.Sum256([]byte("diff-" + strconv.Itoa(i)))
		sig, err := signer.SignHash(h[:])
		require.NoError(t, err)
		variants := [][]byte{sig, highS(sig)}
		for v := byte(0); v < 6; v++ {
			variants = append(variants, withV(sig, v))
		}
		junk := sha256.Sum256([]byte("junk" + strconv.Itoa(i)))
		variants = append(variants, append(append(bytes.Clone(junk[:]), junk[:]...), byte(i%4)))
		for _, sg := range variants {
			q := refRecover(h[:], sg)
			want := q != nil && bytes.Equal(q.compressed(), pub) && new(big.Int).SetBytes(sg[32:64]).Cmp(halfN) <= 0
			require.Equal(t, want, ver.VerifyHash(sg, h[:]) == nil, "i=%d sig=%x", i, sg)
		}
	}
}
