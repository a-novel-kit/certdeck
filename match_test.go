package certdeck_test

import (
	"crypto/x509"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/a-novel-kit/certdeck"
	"github.com/a-novel-kit/certdeck/internal/certs"
)

func TestMatch(t *testing.T) {
	testCases := []struct {
		name string

		chain1 []*x509.Certificate
		chain2 []*x509.Certificate

		expect error
	}{
		{
			name: "equal chains",

			chain1: []*x509.Certificate{
				certs.Chain1Cert,
				certs.Chain2Cert,
			},
			chain2: []*x509.Certificate{
				certs.Chain1Cert,
				certs.Chain2Cert,
			},
		},
		{
			name: "not same length",

			chain1: []*x509.Certificate{
				certs.Chain1Cert,
			},
			chain2: []*x509.Certificate{
				certs.Chain1Cert,
				certs.Chain2Cert,
			},

			expect: certdeck.ErrCertMismatch,
		},
		{
			name: "not equal chains",

			chain1: []*x509.Certificate{
				certs.Chain1Cert,
				certs.Chain2Cert,
			},
			chain2: []*x509.Certificate{
				certs.Chain1Cert,
				certs.Chain3Cert,
			},

			expect: certdeck.ErrCertMismatch,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := certdeck.Match(tc.chain1, tc.chain2)
			require.ErrorIs(t, err, tc.expect)
		})
	}
}

func TestMatchKey(t *testing.T) {
	testCases := []struct {
		name string

		keyPub interface{}
		certs  []*x509.Certificate

		expect error
	}{
		{
			name: "valid keys",

			keyPub: certs.Chain1Cert.PublicKey,
			certs: []*x509.Certificate{
				certs.Chain1Cert,
				certs.Chain2Cert,
			},
		},
		{
			name: "empty keys",

			keyPub: nil,
			certs:  []*x509.Certificate{},
		},
		{
			name: "invalid keys",

			keyPub: certs.Chain3Key.Public(),
			certs: []*x509.Certificate{
				certs.Chain1Cert,
				certs.Chain2Cert,
			},

			expect: certdeck.ErrCertKeyMismatch,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			err := certdeck.MatchKey(testCase.keyPub, testCase.certs)
			require.ErrorIs(t, err, testCase.expect)
		})
	}
}
