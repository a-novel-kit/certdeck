package certdeck_test

import (
	"crypto/rsa"
	"crypto/x509"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/a-novel-kit/certdeck"
	testcerts "github.com/a-novel-kit/certdeck/internal/certs"
)

func TestDER(t *testing.T) {
	certs := []*x509.Certificate{testcerts.Chain1Cert, testcerts.Chain2Cert, testcerts.Chain3Cert}

	der := certdeck.CertsToDER(certs...)

	decoded, err := certdeck.DERToCerts(der)
	require.NoError(t, err)
	require.NoError(t, certdeck.Match(certs, decoded))
}

func TestDERInline(t *testing.T) {
	certs := []*x509.Certificate{testcerts.Chain1Cert, testcerts.Chain2Cert, testcerts.Chain3Cert}

	der := certdeck.CertsToDERInline(certs...)

	decoded, err := certdeck.DERInlineToCerts(der)
	require.NoError(t, err)
	require.NoError(t, certdeck.Match(certs, decoded))
}

func TestPEM(t *testing.T) {
	certs := []*x509.Certificate{testcerts.Chain1Cert, testcerts.Chain2Cert, testcerts.Chain3Cert}

	pem := certdeck.CertsToPEM(certs...)

	decoded, err := certdeck.PEMToCerts(pem)
	require.NoError(t, err)
	require.NoError(t, certdeck.Match(certs, decoded))
}

func TestPEMInline(t *testing.T) {
	certs := []*x509.Certificate{testcerts.Chain1Cert, testcerts.Chain2Cert, testcerts.Chain3Cert}

	pem := certdeck.CertsToPEMInline(certs...)

	decoded, err := certdeck.PEMInlineToCerts(pem)
	require.NoError(t, err)
	require.NoError(t, certdeck.Match(certs, decoded))
}

func TestBase64(t *testing.T) {
	certs := []*x509.Certificate{testcerts.Chain1Cert, testcerts.Chain2Cert, testcerts.Chain3Cert}

	base64 := certdeck.CertsToBase64(certs...)

	decoded, err := certdeck.Base64ToCerts(base64)
	require.NoError(t, err)
	require.NoError(t, certdeck.Match(certs, decoded))
}

func TestKeyDER(t *testing.T) {
	key := testcerts.Chain1Key

	der, err := certdeck.KeyToDER(key)
	require.NoError(t, err)

	decoded, err := certdeck.DERToKey(der)
	require.NoError(t, err)
	require.True(t, key.(*rsa.PrivateKey).Equal(decoded))
}

func TestKeyPEM(t *testing.T) {
	key := testcerts.Chain1Key

	pem, err := certdeck.KeyToPEM(key)
	require.NoError(t, err)

	decoded, err := certdeck.PEMToKey(pem)
	require.NoError(t, err)
	require.True(t, key.(*rsa.PrivateKey).Equal(decoded))
}
