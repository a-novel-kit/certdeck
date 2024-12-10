package providers

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"regexp"
	"sort"

	"github.com/a-novel-kit/certdeck"
)

// SortCreatedAt sorts the files by their creation time, with the most recent files first.
func SortCreatedAt(files []os.FileInfo) []os.FileInfo {
	sort.SliceStable(files, func(i, j int) bool {
		return files[i].ModTime().After(files[j].ModTime())
	})
	return files
}

// SortName sorts files by their name, in descending order.
func SortName(files []os.FileInfo) []os.FileInfo {
	sort.SliceStable(files, func(i, j int) bool {
		return files[i].Name() > files[j].Name()
	})
	return files
}

type fileProvider struct {
	fs fs.FS

	id string

	certsPattern *regexp.Regexp
	keysPattern  *regexp.Regexp

	sortCerts func([]os.FileInfo) []os.FileInfo
	sortKeys  func([]os.FileInfo) []os.FileInfo
}

func (provider *fileProvider) ID() string {
	return provider.id
}

func (provider *fileProvider) Retrieve() (certdeck.CollectionRow, error) {
	var certFiles []os.FileInfo
	var keyFiles []os.FileInfo

	err := fs.WalkDir(provider.fs, ".", func(_ string, d fs.DirEntry, err error) error {
		if err != nil {
			return fmt.Errorf("walk directory: %w", err)
		}

		if d.IsDir() {
			return nil
		}

		if provider.keysPattern.MatchString(d.Name()) {
			// Read file info.
			fileInfo, err := d.Info()
			if err != nil {
				return fmt.Errorf("get file info for %s: %w", d.Name(), err)
			}

			keyFiles = append(keyFiles, fileInfo)
		} else if provider.certsPattern.MatchString(d.Name()) {
			// Read file info.
			fileInfo, err := d.Info()
			if err != nil {
				return fmt.Errorf("get file info for %s: %w", d.Name(), err)
			}

			certFiles = append(certFiles, fileInfo)
		}

		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("walk root directory: %w", err)
	}

	// Sort files.
	certFiles = provider.sortCerts(certFiles)
	keyFiles = provider.sortKeys(keyFiles)

	// Read files.
	certsRaw := make([][]byte, len(certFiles))
	for pos, certFile := range certFiles {
		certData, err := fs.ReadFile(provider.fs, certFile.Name())
		if err != nil {
			return nil, fmt.Errorf("read certificate file %s: %w", certFile.Name(), err)
		}

		certsRaw[pos] = certData
	}

	if len(keyFiles) == 0 {
		return nil, errors.New("no key file found")
	}
	if len(certFiles) == 0 {
		return nil, errors.New("no certificate file found")
	}

	keyRaw, err := fs.ReadFile(provider.fs, keyFiles[0].Name())
	if err != nil {
		return nil, fmt.Errorf("read key file %s: %w", keyFiles[0].Name(), err)
	}

	certs, err := certdeck.PEMOrDERToCerts(certsRaw)
	if err != nil {
		return nil, fmt.Errorf("parse certificates: %w", err)
	}
	key, err := certdeck.PEMOrDerToKey(keyRaw)
	if err != nil {
		return nil, fmt.Errorf("parse private key: %w", err)
	}

	keyPEM, err := certdeck.KeyToPEM(key)
	if err != nil {
		return nil, fmt.Errorf("convert private key to PEM: %w", err)
	}

	return &certdeck.CollectionRowBase{
		Certs:      certs,
		CertKey:    key,
		CertsPEM:   certdeck.CertsToPEM(certs...),
		CertKeyPEM: keyPEM,
	}, nil
}

type FileProviderConfig struct {
	// FS is the file system to use to search for files.
	//
	// If not provided, the updater will read every file in BasePath.
	FS fs.FS

	// ID is the identifier of the updater.
	ID string

	// CertsPattern is the pattern to use to search for certificate files.
	//
	// If nil, the default pattern is `\.crt$`.
	CertsPattern *regexp.Regexp
	// KeysPattern is the pattern to use to search for key files.
	//
	// If nil, the default pattern is `\.key$`.
	KeysPattern *regexp.Regexp

	// SortCerts is the function to use to sort the certificate files.
	//
	// Certificates from those file will be parsed in a chain, where the first certificate is the leaf.
	//
	// SortCreatedAt is used by default.
	SortCerts func([]os.FileInfo) []os.FileInfo
	// SortKeys is the function to use to sort the key files.
	//
	// Only the most recent key will be used.
	//
	// SortCreatedAt is used by default.
	SortKeys func([]os.FileInfo) []os.FileInfo
}

// NewFile returns a new certdeck.CertsProvider that reads certificates and keys from a filesystem.
//
// Files can be either PEM or DER encoded, and this updater supports mixing both together.
func NewFile(config *FileProviderConfig) (certdeck.CertsProvider, error) {
	certsPattern := config.CertsPattern
	keysPattern := config.KeysPattern

	if certsPattern == nil {
		certsPattern = regexp.MustCompile(`\.crt$`)
	}
	if keysPattern == nil {
		keysPattern = regexp.MustCompile(`\.key$`)
	}

	sortCerts := config.SortCerts
	if sortCerts == nil {
		sortCerts = SortCreatedAt
	}

	sortKeys := config.SortKeys
	if sortKeys == nil {
		sortKeys = SortCreatedAt
	}

	return &fileProvider{
		fs: config.FS,

		id: config.ID,

		certsPattern: certsPattern,
		keysPattern:  keysPattern,

		sortCerts: sortCerts,
		sortKeys:  sortKeys,
	}, nil
}
