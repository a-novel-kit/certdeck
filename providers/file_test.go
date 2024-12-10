package providers_test

import (
	"crypto/rsa"
	"crypto/x509"
	"regexp"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/a-novel-kit/certdeck"
	"github.com/a-novel-kit/certdeck/internal/certs"
	"github.com/a-novel-kit/certdeck/providers"
)

func TestFileUpdater(t *testing.T) {
	t.Run("basic", func(t *testing.T) {
		updater, err := providers.NewFile(&providers.FileProviderConfig{
			FS: certs.FS,

			ID: "foo",

			CertsPattern: regexp.MustCompile(`chain-.*-cert\.pem$`),
			KeysPattern:  regexp.MustCompile(`chain-.*-keypair\.pem$`),
		})
		require.NoError(t, err)
		require.Equal(t, "foo", updater.ID())

		row, err := updater.Retrieve()
		require.NoError(t, err)
		require.Len(t, row.Certificates(), 3)
		require.NoError(t, certdeck.Match(
			[]*x509.Certificate{certs.Chain1Cert, certs.Chain2Cert, certs.Chain3Cert},
			row.Certificates(),
		))
		require.True(t, certs.Chain1Key.(*rsa.PrivateKey).Equal(row.Key()))

		certsFromPEM, err := certdeck.PEMToCerts(row.CertificatesPEM())
		require.NoError(t, err)
		require.NoError(t, certdeck.Match(
			[]*x509.Certificate{certs.Chain1Cert, certs.Chain2Cert, certs.Chain3Cert},
			certsFromPEM,
		))

		keyFromPEM, err := certdeck.PEMToKey(row.KeyPEM())
		require.NoError(t, err)
		require.True(t, certs.Chain1Key.(*rsa.PrivateKey).Equal(keyFromPEM))
	})

	t.Run("sort", func(t *testing.T) {
		updater, err := providers.NewFile(&providers.FileProviderConfig{
			FS: certs.FS,

			ID: "foo",

			CertsPattern: regexp.MustCompile(`chain-.*-cert\.pem$`),
			KeysPattern:  regexp.MustCompile(`chain-.*-keypair\.pem$`),

			SortCerts: providers.SortName,
			SortKeys:  providers.SortName,
		})
		require.NoError(t, err)
		require.Equal(t, "foo", updater.ID())

		row, err := updater.Retrieve()
		require.NoError(t, err)
		require.Len(t, row.Certificates(), 3)
		require.NoError(t, certdeck.Match(
			[]*x509.Certificate{certs.Chain3Cert, certs.Chain2Cert, certs.Chain1Cert},
			row.Certificates(),
		))
		require.True(t, certs.Chain3Key.(*rsa.PrivateKey).Equal(row.Key()))
	})

	t.Run("no key", func(t *testing.T) {
		updater, err := providers.NewFile(&providers.FileProviderConfig{
			FS: certs.FS,

			ID: "foo",

			CertsPattern: regexp.MustCompile(`chain-.*-cert\.pem$`),
			KeysPattern:  regexp.MustCompile(`foo\.pem$`),
		})
		require.NoError(t, err)
		require.Equal(t, "foo", updater.ID())

		_, err = updater.Retrieve()
		require.Error(t, err)
	})

	t.Run("no cert", func(t *testing.T) {
		updater, err := providers.NewFile(&providers.FileProviderConfig{
			FS: certs.FS,

			ID: "foo",

			CertsPattern: regexp.MustCompile(`foo\.pem$`),
			KeysPattern:  regexp.MustCompile(`chain-.*-keypair\.pem$`),
		})
		require.NoError(t, err)
		require.Equal(t, "foo", updater.ID())

		_, err = updater.Retrieve()
		require.Error(t, err)
	})
}
