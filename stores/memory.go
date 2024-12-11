package stores

import (
	"context"
	"math/big"

	"github.com/a-novel-kit/certdeck"
)

type MemoryStore struct {
	serials map[string]bool
	certdeck.SerialStore
}

func (m *MemoryStore) Insert(_ context.Context, serial *big.Int) error {
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

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{}
}
