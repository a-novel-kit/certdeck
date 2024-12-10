package certdeck

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
)

var ErrAlreadyExists = errors.New("serial number already exists")

// SerialStore keeps track of used serial numbers.
type SerialStore interface {
	// Insert a new serial number in the store. If the serial number is already taken, this must return
	// ErrAlreadyExists.
	Insert(ctx context.Context, serial *big.Int) error
}

// GenerateSerial generates a random serial number for a certificate.
func GenerateSerial() (*big.Int, error) {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 160))
	if err != nil {
		return nil, fmt.Errorf("generate serial number: %w", err)
	}

	return serial, nil
}

const SerialGenerationMaxRetries = 5

func GenerateSerialWithStore(ctx context.Context, store SerialStore, maxRetries int) (*big.Int, error) {
	var retries int
	for {
		if retries >= maxRetries {
			return nil, ErrAlreadyExists
		}

		serial, err := GenerateSerial()
		if err != nil {
			return nil, fmt.Errorf("generate: %w", err)
		}

		err = store.Insert(ctx, serial)
		if err == nil {
			return serial, nil
		}

		if !errors.Is(err, ErrAlreadyExists) {
			return nil, fmt.Errorf("insert: %w", err)
		}

		retries++
	}
}
