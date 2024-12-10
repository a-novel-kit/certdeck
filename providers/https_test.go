package providers_test

import (
	"crypto/rsa"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/a-novel-kit/certdeck"
	"github.com/a-novel-kit/certdeck/internal/certs"
	"github.com/a-novel-kit/certdeck/providers"
)

func TestHTTPS(t *testing.T) {
	t.Run("basic", func(t *testing.T) {
		certsHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(append(
				certs.Chain1CertPEM,
				certs.Chain2CertPEM...,
			))
		})
		keysHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(certs.Chain1KeypairPEM)
		})

		certsServer := httptest.NewServer(certsHandler)
		defer certsServer.Close()
		keysServer := httptest.NewServer(keysHandler)
		defer keysServer.Close()

		updater := providers.NewHTTPS(&providers.HTTPSProviderConfig{
			ID: "foo",

			CertsReq: func() (*http.Request, error) {
				return http.NewRequest(http.MethodGet, certsServer.URL, nil)
			},
			KeyReq: func() (*http.Request, error) {
				return http.NewRequest(http.MethodGet, keysServer.URL, nil)
			},
		})
		require.Equal(t, "foo", updater.ID())

		row, err := updater.Retrieve()
		require.NoError(t, err)
		require.Len(t, row.Certificates(), 2)
		require.NoError(t, certdeck.Match(
			[]*x509.Certificate{certs.Chain1Cert, certs.Chain2Cert},
			row.Certificates(),
		))
		require.True(t, certs.Chain1Key.(*rsa.PrivateKey).Equal(row.Key()))

		certsFromPEM, err := certdeck.PEMToCerts(row.CertificatesPEM())
		require.NoError(t, err)
		require.NoError(t, certdeck.Match(
			[]*x509.Certificate{certs.Chain1Cert, certs.Chain2Cert},
			certsFromPEM,
		))

		keyFromPEM, err := certdeck.PEMToKey(row.KeyPEM())
		require.NoError(t, err)
		require.True(t, certs.Chain1Key.(*rsa.PrivateKey).Equal(keyFromPEM))
	})

	t.Run("key server error", func(t *testing.T) {
		certsHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(append(
				certs.Chain1CertPEM,
				certs.Chain2CertPEM...,
			))
		})
		keysHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write(certs.Chain1KeypairPEM)
		})

		certsServer := httptest.NewServer(certsHandler)
		defer certsServer.Close()
		keysServer := httptest.NewServer(keysHandler)
		defer keysServer.Close()

		updater := providers.NewHTTPS(&providers.HTTPSProviderConfig{
			ID: "foo",

			CertsReq: func() (*http.Request, error) {
				return http.NewRequest(http.MethodGet, certsServer.URL, nil)
			},
			KeyReq: func() (*http.Request, error) {
				return http.NewRequest(http.MethodGet, keysServer.URL, nil)
			},
		})
		require.Equal(t, "foo", updater.ID())

		_, err := updater.Retrieve()
		require.Error(t, err)
	})

	t.Run("cert server error", func(t *testing.T) {
		certsHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write(append(
				certs.Chain1CertPEM,
				certs.Chain2CertPEM...,
			))
		})
		keysHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(certs.Chain1KeypairPEM)
		})

		certsServer := httptest.NewServer(certsHandler)
		defer certsServer.Close()
		keysServer := httptest.NewServer(keysHandler)
		defer keysServer.Close()

		updater := providers.NewHTTPS(&providers.HTTPSProviderConfig{
			ID: "foo",

			CertsReq: func() (*http.Request, error) {
				return http.NewRequest(http.MethodGet, certsServer.URL, nil)
			},
			KeyReq: func() (*http.Request, error) {
				return http.NewRequest(http.MethodGet, keysServer.URL, nil)
			},
		})
		require.Equal(t, "foo", updater.ID())

		_, err := updater.Retrieve()
		require.Error(t, err)
	})
}
