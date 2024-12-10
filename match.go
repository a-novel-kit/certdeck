package certdeck

import (
	"crypto/x509"
	"errors"
	"fmt"
	"reflect"
)

var (
	ErrCertMismatch    = errors.New("certificate chains are not semantically equal")
	ErrCertKeyMismatch = errors.New("public key mismatch")
)

// Match checks if two certificate chains are semantically equal.
func Match(chain1, chain2 []*x509.Certificate) error {
	if len(chain1) != len(chain2) {
		return ErrCertMismatch
	}

	for pos := range chain1 {
		if !chain1[pos].Equal(chain2[pos]) {
			return ErrCertMismatch
		}
	}

	return nil
}

// MatchKey checks if the public key matches the certificate.
func MatchKey(keyPub interface{}, certs []*x509.Certificate) error {
	if len(certs) == 0 || keyPub == nil {
		return nil
	}

	certPub := certs[0].PublicKey
	if !reflect.DeepEqual(certPub, keyPub) {
		return fmt.Errorf("%w:\n\tgot %[2]s (%[2]T)\n\twanted %[3]s (%[3]T)", ErrCertKeyMismatch, certPub, keyPub)
	}

	return nil
}
