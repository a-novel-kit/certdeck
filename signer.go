package certdeck

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/samber/lo"
)

var IPLocalHost = []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback}

type Template struct {
	// Exp sets the expiration time of the certificate.
	//
	// It is set to 365 days by default.
	Exp time.Duration

	// Name is the subject of the certificate.
	Name pkix.Name

	// IPAddresses is a list of IP addresses that the certificate is valid for.
	IPAddresses []net.IP

	// DNSNames is a list of DNS names that the certificate is valid for.
	DNSNames []string

	// LeafOnly revokes the ability of the issued certificate to sign other certificates.
	LeafOnly bool
}

type Signer interface {
	// Sign a CertKey with a template, returning the certificate.
	//
	// Pub CertKey is the CertKey of the certificate that will be issued. It must be one of the following supported types:
	//  - *rsa.PublicKey
	//  - *ecdsa.PublicKey
	//  - ed25519.PublicKey
	//
	// KeyID must be a random, unique identifier for the certificate. It can be derived from the public CertKey.
	// Depending on the type of your public CertKey, you can use any of the provided hashers in this package:
	//  - HashRSA
	//  - HashECDSA
	//  - HashED25519
	Sign(ctx context.Context, key any, keyID []byte, template *Template) (*x509.Certificate, error)
	// Rotate updates the issuer chain and the CertKey used to sign the certificates.
	Rotate(issuers []*x509.Certificate, issuerKey crypto.Signer)
}

type signerImpl struct {
	serialStore SerialStore

	issuers   []*x509.Certificate
	issuerKey crypto.Signer

	sync.RWMutex
}

func (signer *signerImpl) Rotate(issuers []*x509.Certificate, issuerKey crypto.Signer) {
	signer.Lock()
	defer signer.Unlock()

	signer.issuers = issuers
	signer.issuerKey = issuerKey
}

func (signer *signerImpl) sign(template *x509.Certificate, key any, leafOnly bool) ([]byte, error) {
	ca := signer.issuers[0]
	caKey := signer.issuerKey

	template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}
	template.AuthorityKeyId = ca.SubjectKeyId
	template.Issuer = ca.Subject

	if !leafOnly {
		template.BasicConstraintsValid = true
		template.IsCA = true
		template.KeyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign
	} else {
		template.KeyUsage = x509.KeyUsageDigitalSignature
	}

	raw, err := x509.CreateCertificate(rand.Reader, template, ca, key, caKey)
	if err != nil {
		return nil, fmt.Errorf("create certificate: %w", err)
	}

	return raw, nil
}

func (signer *signerImpl) signCA(template *x509.Certificate, key crypto.Signer) ([]byte, error) {
	template.ExtKeyUsage = []x509.ExtKeyUsage{
		x509.ExtKeyUsageClientAuth,
		x509.ExtKeyUsageServerAuth,
	}
	template.KeyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign
	template.IsCA = true
	template.BasicConstraintsValid = true
	template.AuthorityKeyId = template.SubjectKeyId

	raw, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		return nil, fmt.Errorf("create certificate authority: %w", err)
	}

	return raw, nil
}

func (signer *signerImpl) Sign(
	ctx context.Context, key any, keyID []byte, template *Template,
) (*x509.Certificate, error) {
	const year = 365 * 24 * time.Hour

	serial, err := GenerateSerialWithStore(ctx, signer.serialStore, SerialGenerationMaxRetries)
	if err != nil {
		return nil, fmt.Errorf("serial number: %w", err)
	}

	signer.RLock()
	defer signer.RUnlock()

	now := time.Now()
	exp := now.Add(lo.CoalesceOrEmpty(template.Exp, year))

	x509Template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      template.Name,
		IPAddresses:  template.IPAddresses,
		NotBefore:    now,
		NotAfter:     exp,
		SubjectKeyId: keyID,
		DNSNames:     template.DNSNames,
	}

	var raw []byte

	// Self-signed certificate.
	if len(signer.issuers) == 0 {
		privateKey, ok := key.(crypto.Signer)
		if !ok {
			return nil, errors.New("self signed CA requires a private key")
		}

		raw, err = signer.signCA(x509Template, privateKey)
	} else {
		raw, err = signer.sign(x509Template, key, template.LeafOnly)
	}
	if err != nil {
		return nil, fmt.Errorf("sign certificate: %w", err)
	}

	cert, err := x509.ParseCertificate(raw)
	if err != nil {
		return nil, fmt.Errorf("parse certificate: %w", err)
	}

	return cert, nil
}

type SignerConfig struct {
	// SerialStore keeps track of used serial numbers.
	SerialStore SerialStore
	// IssuerChain is a list of certificates that will be used to sign the certificate.
	IssuerChain []*x509.Certificate
	// IssuerKey is the CertKey that will be used to sign the certificate. It must be the CertKey of the first
	// certificate in the IssuerChain list.
	//
	// The public CertKey of the IssuerKey must be of a supported type:
	//  - *rsa.PublicKey
	//  - *ecdsa.PublicKey
	//  - ed25519.PublicKey
	IssuerKey crypto.Signer
}

func NewSigner(config *SignerConfig) Signer {
	return &signerImpl{
		serialStore: config.SerialStore,
		issuers:     config.IssuerChain,
		issuerKey:   config.IssuerKey,
	}
}
