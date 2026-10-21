package crypto

import (
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	test "github.com/unicitynetwork/bft-go-base/testutils"
)

type SigningTestSuite struct {
	suite.Suite
}

func TestSigningTestSuite(t *testing.T) {
	suite.Run(t, new(SigningTestSuite))
}

func (s *SigningTestSuite) Test_InvalidPrivateKeySizes() {
	signer, err := NewInMemorySecp256K1SignerFromKey(nil)
	require.Error(s.T(), err)
	require.Nil(s.T(), signer)

	signer2, err := NewInMemorySecp256K1SignerFromKey(make([]byte, 33))
	require.Error(s.T(), err)
	require.Nil(s.T(), signer2)
}

func (s *SigningTestSuite) Test_VerifierFromSigner() {
	signer, err := NewInMemorySecp256K1Signer()
	require.NoError(s.T(), err)

	verifier, err := signer.Verifier()
	require.NoError(s.T(), err)
	s.assertSignAndVerify(signer, verifier)
}

func (s *SigningTestSuite) Test_VerifierFromKeyBytes() {
	signer, err := NewInMemorySecp256K1Signer()
	require.NoError(s.T(), err)

	verifier1, err := signer.Verifier()
	require.NoError(s.T(), err)
	pubkey, err := verifier1.MarshalPublicKey()
	require.NoError(s.T(), err)
	require.Len(s.T(), pubkey, CompressedSecp256K1PublicKeySize, "pubkey length is not expected compressed key size")

	verifier, err := NewVerifierSecp256k1(pubkey)
	require.NoError(s.T(), err)
	s.assertSignAndVerify(signer, verifier)

	// Try to marshal public again from verifier that is created from compressed key
	pubkeyAgain, err := verifier.MarshalPublicKey()
	require.NoError(s.T(), err)
	require.Len(s.T(), pubkeyAgain, CompressedSecp256K1PublicKeySize, "pubkey length is not expected compressed key size")

	verifierAgain, err := NewVerifierSecp256k1(pubkeyAgain)
	require.NoError(s.T(), err)
	s.assertSignAndVerify(signer, verifierAgain)
}

func (s *SigningTestSuite) Test_MarshallingPrivateKey() {
	signer, err := NewInMemorySecp256K1Signer()
	require.NoError(s.T(), err)

	privKey, err := signer.MarshalPrivateKey()
	require.NoError(s.T(), err)

	signerFromKey, err := NewInMemorySecp256K1SignerFromKey(privKey)
	require.NoError(s.T(), err)

	verifier, err := signerFromKey.Verifier()
	require.NoError(s.T(), err)

	s.assertSignAndVerify(signerFromKey, verifier)
}

func TestSignerNilArguments(t *testing.T) {
	var signer InMemorySecp256K1Signer

	bytes, err := signer.SignBytes([]byte{1, 2, 3})
	require.Error(t, err)
	require.Nil(t, bytes)
}

func TestSignerNilData(t *testing.T) {
	signer, err := NewInMemorySecp256K1Signer()
	require.NoError(t, err)

	bytes, err := signer.SignBytes(nil)
	require.Error(t, err)
	require.Nil(t, bytes)
}

func TestSignNilHash(t *testing.T) {
	signer, err := NewInMemorySecp256K1Signer()
	require.NoError(t, err)
	bytes, err := signer.SignHash(nil)
	require.Error(t, err)
	require.Nil(t, bytes)
}

func TestVerifyNilHash(t *testing.T) {
	signer, err := NewInMemorySecp256K1Signer()
	require.NoError(t, err)
	verifier, err := signer.Verifier()
	require.NoError(t, err)

	err = verifier.VerifyHash(test.RandomBytes(64), nil)
	require.Error(t, err)
}

func TestSignAndVerifyHash(t *testing.T) {
	signer, err := NewInMemorySecp256K1Signer()
	require.NoError(t, err)
	verifier, err := signer.Verifier()
	require.NoError(t, err)

	hash := test.RandomBytes(32)
	signature, err := signer.SignHash(hash)
	require.NoError(t, err)
	err = verifier.VerifyHash(signature, hash)
	require.NoError(t, err)
}

func TestVerifierNilVerifier(t *testing.T) {
	var verifier verifierSecp256k1

	err := verifier.VerifyBytes([]byte{1}, []byte{2})
	require.Error(t, err)

	key, err := verifier.MarshalPublicKey()
	require.Error(t, err)
	require.Nil(t, key)
}

func TestVerifierIllegalInput(t *testing.T) {
	signer, err := NewInMemorySecp256K1Signer()
	require.NoError(t, err)
	verifier, err := signer.Verifier()
	require.NoError(t, err)

	data := []byte{1, 2, 3, 4}
	sig, err := signer.SignBytes(data)
	require.NoError(t, err)

	err = verifier.VerifyBytes([]byte{1, 2}, data)
	require.Error(t, err, "verifying signature with illegal size must fail")

	err = verifier.VerifyBytes(sig, append(data, 5))
	require.Error(t, err, "verifying not matching data and signature must fail")
}

func (s *SigningTestSuite) assertSignAndVerify(signer Signer, verifier Verifier) {
	signAndVerifyBytes(s.T(), signer, verifier)
	signAndVerifyNoRecoveryID(s.T(), signer, verifier)
}

func signAndVerifyNoRecoveryID(t *testing.T, signer Signer, verifier Verifier) {
	data := []byte{1, 2, 3}
	sig, err := signer.SignBytes(data)
	require.NoError(t, err)

	sigWithoutRecoveryID := sig[:len(sig)-1]

	// the canonical verifier rejects a signature without recovery ID; the compact contract accepts it
	require.Error(t, verifier.VerifyBytes(sigWithoutRecoveryID, data))
	require.NoError(t, verifier.(CompactVerifier).VerifyCompactBytes(sigWithoutRecoveryID, data))
}

func signAndVerifyBytes(t *testing.T, signer Signer, verifier Verifier) {
	data := []byte{1, 2, 3}
	sig, err := signer.SignBytes(data)
	require.NoError(t, err)

	err = verifier.VerifyBytes(sig, data)
	require.NoError(t, err)
}

func TestVerifyHashBindsTheRecoveryID(t *testing.T) {
	signer, err := NewInMemorySecp256K1Signer()
	require.NoError(t, err)
	verifier, err := signer.Verifier()
	require.NoError(t, err)
	hash := test.RandomBytes(32)
	sig, err := signer.SignHash(hash)
	require.NoError(t, err)
	require.NoError(t, verifier.VerifyHash(sig, hash))
	for v := 0; v < 256; v++ {
		mutated := append([]byte(nil), sig...)
		mutated[64] = byte(v)
		if byte(v) == sig[64] {
			require.NoError(t, verifier.VerifyHash(mutated, hash))
			continue
		}
		require.Error(t, verifier.VerifyHash(mutated, hash), "recovery id %d must be rejected", v)
	}
	require.Error(t, verifier.VerifyHash(sig[:64], hash), "compact signature is not a canonical signature")
	require.Error(t, verifier.VerifyHash(append(append([]byte(nil), sig...), 0), hash))
	require.NoError(t, verifier.(CompactVerifier).VerifyCompactHash(sig[:64], hash))
}
