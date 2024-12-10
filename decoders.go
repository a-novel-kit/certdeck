package certdeck

import (
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
)

func DERToCerts(data [][]byte) ([]*x509.Certificate, error) {
	certs := make([]*x509.Certificate, len(data))

	for pos, certData := range data {
		cert, err := x509.ParseCertificate(certData)
		if err != nil {
			return nil, err
		}

		certs[pos] = cert
	}

	return certs, nil
}

func PEMToCerts(data [][]byte) ([]*x509.Certificate, error) {
	certs := make([]*x509.Certificate, len(data))

	for pos, certData := range data {
		block, _ := pem.Decode(certData)
		if block == nil {
			return nil, errors.New("decode pem block: no block found")
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse certificate: %w", err)
		}

		certs[pos] = cert
	}

	return certs, nil
}

func PEMOrDERToCerts(data [][]byte) ([]*x509.Certificate, error) {
	certs := make([]*x509.Certificate, len(data))

	for pos, certData := range data {
		// Try to decode PEM, then assume it is DER if it fails.
		block, _ := pem.Decode(certData)
		if block != nil {
			certData = block.Bytes
		}

		cert, err := x509.ParseCertificate(certData)
		if err != nil {
			return nil, fmt.Errorf("parse certificate: %w", err)
		}

		certs[pos] = cert
	}

	return certs, nil
}

func DERInlineToCerts(data []byte) ([]*x509.Certificate, error) {
	return x509.ParseCertificates(data)
}

func PEMInlineToCerts(data []byte) ([]*x509.Certificate, error) {
	output := make([]*x509.Certificate, 0)
	for block, rest := pem.Decode(data); block != nil; block, rest = pem.Decode(rest) {
		switch block.Type {
		case "CERTIFICATE":
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("parse certificate: %w", err)
			}

			output = append(output, cert)
		default:
			return nil, fmt.Errorf("parse certificate: unexpected PEM block type %s", block.Type)
		}
	}

	return output, nil
}

func Base64ToCerts(data []string) ([]*x509.Certificate, error) {
	out := make([]*x509.Certificate, len(data))

	for pos, cert := range data {
		// Decode base64 content.
		raw, err := base64.StdEncoding.DecodeString(cert)
		if err != nil {
			return nil, fmt.Errorf("decode certificate: %w", err)
		}

		// Use the std parser.
		out[pos], err = x509.ParseCertificate(raw)
		if err != nil {
			return nil, fmt.Errorf("parse certificate: %w", err)
		}
	}

	return out, nil
}

func DERToKey(data []byte) (crypto.Signer, error) {
	if key, err := x509.ParsePKCS1PrivateKey(data); err == nil {
		return key, nil
	}

	if key, err := x509.ParseECPrivateKey(data); err == nil {
		return key, nil
	}

	if rawKey, err := x509.ParsePKCS8PrivateKey(data); err == nil {
		key, ok := rawKey.(crypto.Signer)
		if !ok {
			return nil, ErrUnsupportedKeyFormat
		}

		return key, nil
	}

	return nil, ErrUnsupportedKeyFormat
}

func PEMToKey(data []byte) (crypto.Signer, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("decode pem block: no block found")
	}

	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}

	if key, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		return key, nil
	}

	if rawKey, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		key, ok := rawKey.(crypto.Signer)
		if !ok {
			return nil, ErrUnsupportedKeyFormat
		}

		return key, nil
	}

	return nil, ErrUnsupportedKeyFormat
}

func PEMOrDerToKey(data []byte) (crypto.Signer, error) {
	block, _ := pem.Decode(data)
	if block != nil {
		data = block.Bytes
	}

	return DERToKey(data)
}
