package certdeck_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"testing"
	"time"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/a-novel-kit/certdeck"
	certdeckmocks "github.com/a-novel-kit/certdeck/mocks"
)

func TestSigner(t *testing.T) {
	store := certdeckmocks.NewMockSerialStore(t)
	store.On("Insert", context.Background(), mock.Anything).Return(nil).Times(3)

	rootSigner := certdeck.NewSigner(&certdeck.SignerConfig{
		SerialStore: store,
	})

	rootKey, err := rsa.GenerateKey(rand.Reader, 8192)
	require.NoError(t, err)

	rootKeyHash := certdeck.HashRSA(&rootKey.PublicKey)

	rootCert, err := rootSigner.Sign(context.Background(), rootKey, rootKeyHash, &certdeck.Template{
		Exp: time.Hour,
		Name: pkix.Name{
			Country:       []string{"FR"},
			Organization:  []string{"A Novel Kit"},
			Locality:      []string{"Paris"},
			Province:      []string{""},
			StreetAddress: []string{"1 rue de la Paix"},
			PostalCode:    []string{"75000"},
		},
		IPAddresses: certdeck.IPLocalHost,
		DNSNames:    []string{"localhost"},
	})
	require.NoError(t, err)
	require.NotNil(t, rootCert)

	// Create a new signer with the root certificate.
	intermediateSigner := certdeck.NewSigner(&certdeck.SignerConfig{
		SerialStore: store,
		IssuerChain: []*x509.Certificate{rootCert},
		IssuerKey:   rootKey,
	})

	intermediateKey, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	require.NoError(t, err)

	intermediateKeyHash := certdeck.HashECDSA(&intermediateKey.PublicKey)

	intermediateCert, err := intermediateSigner.Sign(
		context.Background(), intermediateKey.Public(), intermediateKeyHash,
		&certdeck.Template{
			Exp: time.Hour,
			Name: pkix.Name{
				Country:       []string{"FR"},
				Organization:  []string{"A Novel Kit"},
				Locality:      []string{"Paris"},
				Province:      []string{""},
				StreetAddress: []string{"1 rue de la Paix"},
				PostalCode:    []string{"75000"},
			},
			IPAddresses: certdeck.IPLocalHost,
			DNSNames:    []string{"localhost"},
		},
	)
	require.NoError(t, err)
	require.NotNil(t, intermediateCert)

	// Create a new signer with the intermediate certificate.
	leafSigner := certdeck.NewSigner(&certdeck.SignerConfig{
		SerialStore: store,
		IssuerChain: []*x509.Certificate{intermediateCert, rootCert},
		IssuerKey:   intermediateKey,
	})

	leafKey, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	leafKeyHash := certdeck.HashED25519(&leafKey)

	leafCert, err := leafSigner.Sign(
		context.Background(), leafKey, leafKeyHash,
		&certdeck.Template{
			Exp: time.Hour,
			Name: pkix.Name{
				Country:       []string{"FR"},
				Organization:  []string{"A Novel Kit"},
				Locality:      []string{"Paris"},
				Province:      []string{""},
				StreetAddress: []string{"1 rue de la Paix"},
				PostalCode:    []string{"75000"},
			},
			IPAddresses: certdeck.IPLocalHost,
			DNSNames:    []string{"localhost"},
			LeafOnly:    true,
		},
	)

	require.NoError(t, err)
	require.NotNil(t, leafCert)

	certPool := x509.NewCertPool()
	certPool.AddCert(rootCert)

	intermediatesCertPool := x509.NewCertPool()
	intermediatesCertPool.AddCert(intermediateCert)

	_, err = leafCert.Verify(x509.VerifyOptions{
		Roots:         certPool,
		Intermediates: intermediatesCertPool,
		DNSName:       "localhost",
	})
	require.NoError(t, err)

	store.AssertExpectations(t)
}
