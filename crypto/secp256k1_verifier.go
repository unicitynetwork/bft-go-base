package crypto

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/sha256"
	"errors"
	"fmt"
	"math/big"

	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/secp256k1"
)

var (
	ErrInvalidArgument    = errors.New("invalid nil argument")
	ErrVerificationFailed = errors.New("verification failed")
)

type (
	verifierSecp256k1 struct {
		pubKey []byte
	}
)

var (
	secp256k1N, _  = new(big.Int).SetString("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", 16)
	secp256k1HalfN = new(big.Int).Rsh(secp256k1N, 1)
)

// MaxRecoveryID is the largest valid secp256k1 recovery ID (libsecp256k1 compact recoverable format).
const MaxRecoveryID = 3

// CompressedSecp256K1PublicKeySize is size of public key in compressed format
const CompressedSecp256K1PublicKeySize = 33

// NewVerifierSecp256k1 creates new verifier from an existing Secp256k1 compressed public key.
func NewVerifierSecp256k1(compressedPubKey []byte) (Verifier, error) {
	if len(compressedPubKey) != CompressedSecp256K1PublicKeySize {
		return nil, fmt.Errorf("pubkey must be %d bytes long, but is %d", CompressedSecp256K1PublicKeySize, len(compressedPubKey))
	}
	x, y := secp256k1.DecompressPubkey(compressedPubKey)
	if x == nil && y == nil {
		return nil, fmt.Errorf("public key decompress failed")
	}
	pubkey := secp256k1.S256().Marshal(x, y)
	return &verifierSecp256k1{pubkey}, nil
}

// VerifyBytes hashes the data with SHA256 and verifies it using the public key of the verifier.
func (v *verifierSecp256k1) VerifyBytes(sig []byte, data []byte) error {
	if v == nil || v.pubKey == nil || sig == nil || data == nil {
		return ErrInvalidArgument
	}
	h := sha256.Sum256(data)
	return v.VerifyHash(sig, h[:])
}

// VerifyHash verifies the hash against a canonical recoverable signature using the internal public key.
//
// The signature must be exactly 65 bytes, r[32] || s[32] || v[1], with 1 <= r,s < n, low-S (s <= n/2) and a
// recovery ID v in 0..3 (no 27/28 or EIP-155 interpretation). These cheap checks are followed by exactly one
// public key recovery (Q' = r^-1(sR - zG), one two-term linear combination) and a comparison with the trusted
// key: Q' == Q implies sR = zG + rQ, i.e. ordinary ECDSA validity and the selected recovery branch, so no
// separate ECDSA verification is performed. A digest of zero or >= n is reduced mod n, as in ECDSA. A 64-byte
// compact signature is not a canonical signature and is rejected here; use VerifyCompactHash where that
// primitive is explicitly intended.
func (v *verifierSecp256k1) VerifyHash(sig []byte, hash []byte) error {
	if v == nil || v.pubKey == nil || sig == nil || hash == nil {
		return ErrInvalidArgument
	}
	if len(sig) != ethcrypto.SignatureLength {
		return fmt.Errorf("signature length is %d b (expected %d b)", len(sig), ethcrypto.SignatureLength)
	}
	if len(hash) != ethcrypto.DigestLength {
		return fmt.Errorf("digest length is %d b (expected %d b)", len(hash), ethcrypto.DigestLength)
	}
	if sig[ethcrypto.RecoveryIDOffset] > MaxRecoveryID {
		return fmt.Errorf("%w: recovery id %d out of range", ErrVerificationFailed, sig[ethcrypto.RecoveryIDOffset])
	}
	// 1 <= r < n and 1 <= s <= n/2 (low-S). ValidateSignatureValues is not used: it only admits v in {0,1}.
	r, s := new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:64])
	if r.Sign() == 0 || r.Cmp(secp256k1N) >= 0 || s.Sign() == 0 || s.Cmp(secp256k1HalfN) > 0 {
		return fmt.Errorf("%w: r or s out of range or s is not low", ErrVerificationFailed)
	}
	// the single recovery; the library rejects invalid lifts/decompression and the identity
	recovered, err := secp256k1.RecoverPubkey(hash, sig)
	if err != nil || !bytes.Equal(recovered, v.pubKey) {
		return ErrVerificationFailed
	}
	return nil
}

// VerifyCompactBytes hashes the data with SHA256 and verifies the 64-byte compact signature r||s.
func (v *verifierSecp256k1) VerifyCompactBytes(sig []byte, data []byte) error {
	if v == nil || v.pubKey == nil || sig == nil || data == nil {
		return ErrInvalidArgument
	}
	h := sha256.Sum256(data)
	return v.VerifyCompactHash(sig, h[:])
}

// VerifyCompactHash verifies a 64-byte compact signature r||s (low-S) against the hash. It carries no recovery ID
// and therefore authenticates nothing about one; it is NOT the rule for unicity seal signatures.
func (v *verifierSecp256k1) VerifyCompactHash(sig []byte, hash []byte) error {
	if v == nil || v.pubKey == nil || sig == nil || hash == nil {
		return ErrInvalidArgument
	}
	if len(sig) != ethcrypto.RecoveryIDOffset {
		return fmt.Errorf("compact signature length is %d b (expected %d b)", len(sig), ethcrypto.RecoveryIDOffset)
	}
	if secp256k1.VerifySignature(v.pubKey, hash, sig) {
		return nil
	}
	return ErrVerificationFailed
}

// MarshalPublicKey returns compressed public key, 33 bytes
func (v *verifierSecp256k1) MarshalPublicKey() ([]byte, error) {
	pubkey, err := v.unmarshalPubKey()
	if err != nil {
		return nil, err
	}
	return secp256k1.CompressPubkey(pubkey.X, pubkey.Y), nil
}

func (v *verifierSecp256k1) UnmarshalPubKey() (crypto.PublicKey, error) {
	return v.unmarshalPubKey()
}

func (v *verifierSecp256k1) unmarshalPubKey() (*ecdsa.PublicKey, error) {
	if v == nil || v.pubKey == nil {
		return nil, ErrInvalidArgument
	}
	pubkey, err := ethcrypto.UnmarshalPubkey(v.pubKey)
	if err != nil {
		return nil, fmt.Errorf("convert public key bytes to ECDSA public key failed: %w", err)
	}
	return pubkey, nil
}
