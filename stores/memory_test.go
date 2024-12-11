package stores_test

import (
	"context"
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/a-novel-kit/certdeck"
	"github.com/a-novel-kit/certdeck/stores"
)

func TestMemoryStore(t *testing.T) {
	store := stores.NewMemoryStore()
	require.NotNil(t, store)

	int1 := new(big.Int).SetInt64(1)
	int2 := new(big.Int).SetInt64(2)

	require.NoError(t, store.Insert(context.Background(), int1))
	require.NoError(t, store.Insert(context.Background(), int2))

	require.ErrorIs(t, store.Insert(context.Background(), int1), certdeck.ErrAlreadyExists)
}
