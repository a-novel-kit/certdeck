package certdeck_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/a-novel-kit/certdeck"
	certdeckmocks "github.com/a-novel-kit/certdeck/mocks"
)

func TestGenerateSerialWithStore(t *testing.T) {
	store := certdeckmocks.NewMockSerialStore(t)

	t.Run("first try", func(t *testing.T) {
		store.On("Insert", context.Background(), mock.Anything).Return(nil).Once()

		serial, err := certdeck.GenerateSerialWithStore(context.Background(), store, 5)
		require.NoError(t, err)
		require.NotNil(t, serial)
		require.Len(t, serial.Bytes(), 20)
	})

	t.Run("second try", func(t *testing.T) {
		store.On("Insert", context.Background(), mock.Anything).Return(certdeck.ErrAlreadyExists).Once()
		store.On("Insert", context.Background(), mock.Anything).Return(nil).Once()

		serial, err := certdeck.GenerateSerialWithStore(context.Background(), store, 5)
		require.NoError(t, err)
		require.NotNil(t, serial)
		require.Len(t, serial.Bytes(), 20)
	})

	t.Run("max retries", func(t *testing.T) {
		store.On("Insert", context.Background(), mock.Anything).Return(certdeck.ErrAlreadyExists).Times(3)

		_, err := certdeck.GenerateSerialWithStore(context.Background(), store, 3)
		require.ErrorIs(t, err, certdeck.ErrAlreadyExists)
	})

	store.AssertExpectations(t)
}
