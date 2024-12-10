package certdeck

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
)

var ErrUnsupportedKeyFormat = errors.New("unsupported CertKey format")

func CertsToDER(certificates ...*x509.Certificate) [][]byte {
	derCerts := make([][]byte, len(certificates))

	for pos, cert := range certificates {
		derCerts[pos] = cert.Raw
	}

	return derCerts
}

func CertsToPEM(certificates ...*x509.Certificate) [][]byte {
	pemCerts := make([][]byte, len(certificates))

	for pos, cert := range certificates {
		pemCerts[pos] = pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		})
	}

	return pemCerts
}

func CertsToDERInline(certificates ...*x509.Certificate) []byte {
	var derCerts []byte

	for _, cert := range certificates {
		derCerts = append(derCerts, cert.Raw...)
	}

	return derCerts
}

func CertsToPEMInline(certificates ...*x509.Certificate) []byte {
	var pemCerts []byte

	for _, cert := range certificates {
		pemCerts = append(pemCerts, pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		})...)
	}

	return pemCerts
}

func CertsToBase64(certificates ...*x509.Certificate) []string {
	base64Certs := make([]string, len(certificates))

	for pos, cert := range certificates {
		base64Certs[pos] = base64.StdEncoding.EncodeToString(cert.Raw)
	}

	return base64Certs
}

func KeyToDER(key any) ([]byte, error) {
	switch keyT := key.(type) {
	case *rsa.PrivateKey:
		return x509.MarshalPKCS1PrivateKey(keyT), nil
	case *ecdsa.PrivateKey:
		return x509.MarshalECPrivateKey(keyT)
	default:
		return nil, ErrUnsupportedKeyFormat
	}
}

func KeyToPEM(key any) ([]byte, error) {
	var block *pem.Block
	switch keyT := key.(type) {
	case *rsa.PrivateKey:
		block = &pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(keyT),
		}
	case *ecdsa.PrivateKey:
		encoded, err := x509.MarshalECPrivateKey(keyT)
		if err != nil {
			return nil, err
		}

		block = &pem.Block{
			Type:  "EC PRIVATE KEY",
			Bytes: encoded,
		}
	default:
		return nil, ErrUnsupportedKeyFormat
	}

	return pem.EncodeToMemory(block), nil
}
