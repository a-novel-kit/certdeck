package certs

import (
	"crypto"
	"crypto/x509"
	"embed"
	"encoding/pem"
)

//go:embed *.pem *.der
var FS embed.FS

// Chain 1
var (
	//go:embed chain-1-cert.pem
	Chain1CertPEM []byte
	//go:embed chain-1-keypair.pem
	Chain1KeypairPEM []byte
	//go:embed chain-1-keypair.der
	Chain1KeyDER []byte

	Chain1Key  crypto.Signer
	Chain1Cert *x509.Certificate
)

// Chain 2
var (
	//go:embed chain-2-cert.pem
	Chain2CertPEM []byte
	//go:embed chain-2-keypair.pem
	Chain2KeypairPEM []byte
	//go:embed chain-2-keypair.der
	Chain2KeyDER []byte

	Chain2Key  crypto.Signer
	Chain2Cert *x509.Certificate
)

// Chain 3
var (
	//go:embed chain-3-cert.pem
	Chain3CertPEM []byte
	//go:embed chain-3-keypair.pem
	Chain3KeypairPEM []byte
	//go:embed chain-3-keypair.der
	Chain3KeyDER []byte

	Chain3Key  crypto.Signer
	Chain3Cert *x509.Certificate
)

func parseKeyPair(keypairDER []byte, certPEM []byte) (crypto.Signer, *x509.Certificate) {
	key, err := x509.ParsePKCS8PrivateKey(keypairDER)
	if err != nil {
		panic(err)
	}

	block, _ := pem.Decode(certPEM)
	if block == nil {
		panic("failed to decode certificate")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		panic(err)
	}

	return key.(crypto.Signer), cert
}

func init() {
	Chain1Key, Chain1Cert = parseKeyPair(Chain1KeyDER, Chain1CertPEM)
	Chain2Key, Chain2Cert = parseKeyPair(Chain2KeyDER, Chain2CertPEM)
	Chain3Key, Chain3Cert = parseKeyPair(Chain3KeyDER, Chain3CertPEM)
}
