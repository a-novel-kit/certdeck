package certdeck

import (
	"crypto"
	"crypto/x509"
	"fmt"
	"sync"
	"time"
)

type Collection interface {
	// Get returns the collection of certificates and private CertKey for the given updater.
	Get(updater CertsProvider) (CollectionRow, error)
}

type CollectionRow interface {
	// Certificates returns the underlying certificates chain.
	Certificates() []*x509.Certificate
	// Key returns the underlying private CertKey, that corresponds to the public CertKey of the first certificate in
	// the chain.
	Key() crypto.Signer

	// CertificatesPEM returns the PEM encoded collection of certificates.
	CertificatesPEM() [][]byte
	// KeyPEM returns the PEM encoded private CertKey.
	KeyPEM() []byte
}

type CollectionRowBase struct {
	Certs   []*x509.Certificate
	CertKey crypto.Signer

	CertsPEM   [][]byte
	CertKeyPEM []byte
}

func (row *CollectionRowBase) Fill() error {
	var err error
	row.CertsPEM = CertsToPEM(row.Certs...)

	row.CertKeyPEM, err = KeyToPEM(row.CertKey)
	if err != nil {
		return fmt.Errorf("convert private CertKey to PEM: %w", err)
	}

	return nil
}

// =====================================================================================================================
// INTERFACE METHODS.
// =====================================================================================================================

func (row *CollectionRowBase) Certificates() []*x509.Certificate {
	return row.Certs
}

func (row *CollectionRowBase) Key() crypto.Signer {
	return row.CertKey
}

func (row *CollectionRowBase) CertificatesPEM() [][]byte {
	return row.CertsPEM
}

func (row *CollectionRowBase) KeyPEM() []byte {
	return row.CertKeyPEM
}

// =====================================================================================================================
// COLLECTION.
// =====================================================================================================================

type CertsProvider interface {
	// ID is a unique identifier for the data cached by this updater.
	ID() string
	// Retrieve returns the updated data.
	Retrieve() (CollectionRow, error)
}

type collectionImpl struct {
	cached        map[string]CollectionRow
	cacheTimes    map[string]time.Time
	cacheUpdaters map[string]func() (CollectionRow, error)

	cacheDuration time.Duration

	sync.RWMutex
}

func (collection *collectionImpl) Get(updater CertsProvider) (CollectionRow, error) {
	name := updater.ID()

	collection.RLock()
	if row, ok := collection.cached[name]; ok {
		// Row is cached, data is not refetched.
		if time.Since(collection.cacheTimes[name]) < collection.cacheDuration {
			collection.RUnlock()
			return row, nil
		}
	}
	collection.RUnlock()

	collection.Lock()
	defer collection.Unlock()
	defer collection.purge()

	// Get the update function. Whether data is cached or not, it is expired.
	updateFn, ok := collection.cacheUpdaters[name]
	if !ok {
		collection.cacheUpdaters[name] = updater.Retrieve
		updateFn = updater.Retrieve
	}

	row, err := updateFn()
	if err != nil {
		return nil, fmt.Errorf("get collection for %s: %w", name, err)
	}

	collection.cached[name] = row
	collection.cacheTimes[name] = time.Now()
	return row, nil
}

// purge cleans all data that has expired in the cache, to free up memory.
func (collection *collectionImpl) purge() {
	for name, cachedAt := range collection.cacheTimes {
		if time.Since(cachedAt) > collection.cacheDuration {
			delete(collection.cached, name)
			delete(collection.cacheTimes, name)
			delete(collection.cacheUpdaters, name)
		}
	}
}

func NewCollection(cacheDuration time.Duration) Collection {
	return &collectionImpl{
		cached:        make(map[string]CollectionRow),
		cacheTimes:    make(map[string]time.Time),
		cacheUpdaters: make(map[string]func() (CollectionRow, error)),

		cacheDuration: cacheDuration,
	}
}
