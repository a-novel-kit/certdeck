package providers

import (
	"fmt"
	"io"
	"net/http"

	"github.com/a-novel-kit/certdeck"
)

type httpsProvider struct {
	id       string
	certsReq func() (*http.Request, error)
	keyReq   func() (*http.Request, error)
}

func (provider *httpsProvider) ID() string {
	return provider.id
}

func (provider *httpsProvider) downloadCerts() ([]byte, error) {
	req, err := provider.certsReq()
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read certificate chain: %w", err)
	}

	return data, nil
}

func (provider *httpsProvider) downloadKey() ([]byte, error) {
	req, err := provider.keyReq()
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read key: %w", err)
	}

	return data, nil
}

func (provider *httpsProvider) Retrieve() (certdeck.CollectionRow, error) {
	certsPEMInline, err := provider.downloadCerts()
	if err != nil {
		return nil, fmt.Errorf("download certificates: %w", err)
	}

	keyPEM, err := provider.downloadKey()
	if err != nil {
		return nil, fmt.Errorf("download key: %w", err)
	}

	certs, err := certdeck.PEMInlineToCerts(certsPEMInline)
	if err != nil {
		return nil, fmt.Errorf("parse certificates: %w", err)
	}

	key, err := certdeck.PEMToKey(keyPEM)
	if err != nil {
		return nil, fmt.Errorf("parse private key: %w", err)
	}

	return &certdeck.CollectionRowBase{
		Certs:      certs,
		CertKey:    key,
		CertsPEM:   certdeck.CertsToPEM(certs...),
		CertKeyPEM: keyPEM,
	}, nil
}

type HTTPSProviderConfig struct {
	// ID of the updater. It is recommended to use the base path to the certificate and key files.
	ID string

	// CertsReq returns a request to download the certificate chain.
	CertsReq func() (*http.Request, error)
	// KeyReq returns a request to download the private key.
	KeyReq func() (*http.Request, error)
}

func NewHTTPS(config *HTTPSProviderConfig) certdeck.CertsProvider {
	return &httpsProvider{
		id:       config.ID,
		certsReq: config.CertsReq,
		keyReq:   config.KeyReq,
	}
}
