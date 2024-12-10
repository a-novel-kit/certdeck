# Cert Deck

```go
go get github.com/a-novel-kit/certdeck
```

![GitHub Actions Workflow Status](https://img.shields.io/github/actions/workflow/status/a-novel-kit/certdeck/main.yaml)
[![codecov](https://codecov.io/gh/a-novel-kit/certdeck/graph/badge.svg?token=NDx305I9RN)](https://codecov.io/gh/a-novel-kit/certdeck)

![GitHub repo file or directory count](https://img.shields.io/github/directory-file-count/a-novel-kit/certdeck)
![GitHub code size in bytes](https://img.shields.io/github/languages/code-size/a-novel-kit/certdeck)

![Coverage graph](https://codecov.io/gh/a-novel-kit/certdeck/graphs/sunburst.svg?token=NDx305I9RN)

A x509 certificates management library.

- [Cert Deck](#cert-deck)
  - [Signer](#signer)
  - [Generating certs](#generating-certs)
    - [Certificate keys](#certificate-keys)
  - [Leaf only](#leaf-only)
  - [Self Signed](#self-signed)
  - [Update the issuer chain](#update-the-issuer-chain)
- [Store](#store)
- [Collection](#collection)
  - [Default providers](#default-providers)
    - [File provider](#file-provider)
    - [HTTPS provider](#https-provider)

## Signer

```go
store := newStore()

rootSigner := certdeck.NewSigner(&certdeck.SignerConfig{
	SerialStore: store,
})

rootKey, err := rsa.GenerateKey(rand.Reader, 8192)
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

intermediateSigner := certdeck.NewSigner(&certdeck.SignerConfig{
	SerialStore: store,
	IssuerChain: []*x509.Certificate{rootCert},
	IssuerKey:   rootKey,
})

intermediateKey, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
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

leafSigner := certdeck.NewSigner(&certdeck.SignerConfig{
	SerialStore: store,
	IssuerChain: []*x509.Certificate{intermediateCert, rootCert},
	IssuerKey:   intermediateKey,
})

leafKey, _, err := ed25519.GenerateKey(rand.Reader)
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
```

> The `Signer` interface requires you to provide a store for serial numbers. More information in
> the [Store](#store) section.

### Generating certs

The signer interface uses smart presets, to help you sign valid certificates for web with minimal configuration.

```go
signer := certdeck.NewSigner(&certdeck.SignerConfig{
	SerialStore: store,
	IssuerChain: caChain,
	IssuerKey:   caKey,
})
```

The only 3 parameters you need to initialize a signer are

 - **Store**: a persistent database of assigned serial numbers, to prevent duplicates
 - **IssuerChain**: the chain of certificates used to sign issued certificates
 - **IssuerKey**: the private key used to sign issued certificates, which must match that of the
    first certificate in the issuer chain

Once you have this set, you can call the sign method to issue new certificates. This method wraps the
standard library with some default configuration, so you can focus on what is required to generate a
certificate valid for the web.

```go
cert, err := signer.Sign(context.Background(), key, keyHash, &certdeck.Template{
	// How long the certificate will be valid for. Default is 1 year.
	Exp: time.Hour,
	// Information about the certificate owner.
	Name: pkix.Name{
		Country:       []string{"FR"},
		Organization:  []string{"A Novel Kit"},
		Locality:      []string{"Paris"},
		Province:      []string{""},
		StreetAddress: []string{"1 rue de la Paix"},
		PostalCode:    []string{"75000"},
	},
	// The IP addresses the certificate is valid for.
	IPAddresses: certdeck.IPLocalHost,
	// The DNS names the certificate is valid for.
	DNSNames:    []string{"localhost"},
})
```

> The `Signer` interface is thread-safe, so one instance should be shared across your application.

#### Certificate keys

To generate a certificate, you must also create a private/public key pair for it. The private key is used
to generate signatures, or issue descendant certificates. The public key can be shared, and the certificate
is used to validate it.

X509 only supports the following key types:

 - RSA
 - ECDSA
 - ED25519

Go crypto library already provides generators for those keys. However, another field you must provide is a 
key ID. This ID can be randomly generated, or derived from the public key. This package provides methods
for the second option:

| Key type | Method                 |
|----------|------------------------|
| RSA      | `certdeck.HashRSA`     |
| ECDSA    | `certdeck.HashECDSA`   |
| ED25519  | `certdeck.HashED25519` |


### Leaf only

By default, the generated certificates can be used to issue their own children. While this is useful to
build chains, you should disable this if your certificate is only intended for key validation.

```go
cert, err := signer.Sign(context.Background(), key, keyHash, &certdeck.Template{
	// ... other fields
	LeafOnly: true,
})
```

### Self Signed

You can become your own root, by simply omitting the `IssuerChain` and `IssuerKey` fields, when
initializing the signer.

```go
rootSigner := certdeck.NewSigner(&certdeck.SignerConfig{
	SerialStore: store,
})
```

> If using self-signed certificates, make sure they are added to the root system pool of the target
> machine, when verifying the issued certificates.

### Update the issuer chain

You can update the certificates used by a signer, when new ones are available for example:

```go
signer.Rotate(caChain, caKey)
```

## Store

For security reason, you should provide a way to ensure uniqueness of serial numbers among the certificates
from a given authority. Serial number should be unique even across revoked / expired certificates.

The best way to do this is to keep track of the serial numbers in a persistent database.

The Store is a simple interface, with a single method:

```go
type SerialStore interface {
	Insert(ctx context.Context, serial *big.Int) error
}
```

The `Insert` method saves a new serial number in its database. If the number is already present, it MUST
return the `certdeck.ErrAlreadyExists` error.

Below is an example with an in-memory, volatile store. You should build your own store with a persistent
database instead.

```go
type MemoryStore struct {
	serials map[string]bool
}

func (m *MemoryStore) Insert(ctx context.Context, serial *big.Int) error {
	if m.serials == nil {
		m.serials = make(map[string]bool)
	}

	serialStr := serial.String()
	if m.serials[serialStr] {
		return certdeck.ErrAlreadyExists
	}

	m.serials[serialStr] = true
	return nil
}
```

## Collection

This package provides a `Collection` interface, to manage collections of certificates.

```go
collection := certdeck.NewCollection(time.Hour)

provider := providers.NewHTTPS(&providers.HTTPSProviderConfig{
	ID: "my-website",
	CertsReq: func() (*http.Request, error) {
		return http.NewRequest(http.MethodGet, "https://my-website.com/certs", nil)
	},
	KeyReq: func() (*http.Request, error) {
		return http.NewRequest(http.MethodGet, "https://my-website.com/key", nil)
	},
})

data, err := collection.Get(provider)

certs := data.Certificates()
key := data.Key()
```

The argument of a collection is a duration, that indicates ho long values will be cached before being
fetched again from the provider.

The returned value is a row, that returns the certificate chain and the private signature key, in both
parsed and raw PEM formats.

| Method                               | Description                                                                              |
|--------------------------------------|------------------------------------------------------------------------------------------|
| `Certificates() []*x509.Certificate` | Returns the certificate chain, with the first certificate being the leaf.                |
| `Key() crypto.Signer`                | Returns the private key used to sign the leaf certificate.                               |
| `CertificatesPEM() [][]byte`         | Returns the certificate chain, with the first certificate being the leaf, in PEM format. |
| `KeyPEM() []byte`                    | Returns the private key used to sign the leaf certificate, in PEM format.                |

### Default providers

This package provides the following default providers:

#### File provider

The easier use case is to load certificates from files. First, you need to link your files to your Go code
using a filesystem.

Given the following file tree.

```
- pkg
    - certs
        - files.go
        - 20241012.crt
        - 20241012.key
        - 20241010.crt
        - 20241010.key
```
The content of `files.go` should be:
```go
//go:embed *.crt *.key
var CertsFS embed.FS
```

You can then create a file provider:

```go
provider, err := providers.NewFile(&providers.FileProviderConfig{
	ID: "local",
	FS: CertsFS,
})
```

When loading files, they are sorted by creation date. The most recent one is used as the leaf certificate, and
other are appended in a chain. The key returned is the one of the leaf.

You can customize the behavior of the file provider:

```go
provider, err := providers.NewFile(&providers.FileProviderConfig{
	ID: "local",
	FS: CertsFS,

	// Customize the file pattern used to match certificates.
	CertsPattern: regexp.MustCompile(`\.crt$`)
	// Customize the file pattern used to match keys.
	KeysPattern:  regexp.MustCompile(`\.key$`)
	
	// Custom ordering of cert files. The first one is the leaf, then certificates must be sorted in order.
	SortCerts: providers.SortCreatedAt,
	// Custom ordering of key files. The first one is the key of the leaf, and is the only one actually parsed.
	SortKeys: providers.SortCreatedAt,
})
```

#### HTTPS provider

This provider fetches certificates from a remote server. It requires a function to create a request for the
certificates and the key.

```go
provider, err := providers.NewHTTPS(&providers.HTTPSProviderConfig{
	ID: "my-website",
	CertsReq: func() (*http.Request, error) {
		return http.NewRequest(http.MethodGet, "https://my-website.com/certs", nil)
	},
	KeyReq: func() (*http.Request, error) {
		return http.NewRequest(http.MethodGet, "https://my-website.com/key", nil)
	},
})
```
