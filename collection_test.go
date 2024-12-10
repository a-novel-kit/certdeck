package certdeck_test

import (
	"crypto/x509"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/a-novel-kit/certdeck"
	"github.com/a-novel-kit/certdeck/internal/certs"
	certdeckmocks "github.com/a-novel-kit/certdeck/mocks"
)

func TestCollection(t *testing.T) {
	testRow1 := &certdeck.CollectionRowBase{
		Certs:   []*x509.Certificate{certs.Chain1Cert},
		CertKey: certs.Chain1Key,
	}

	testRow2 := &certdeck.CollectionRowBase{
		Certs:   []*x509.Certificate{certs.Chain2Cert},
		CertKey: certs.Chain2Key,
	}

	testRow3 := &certdeck.CollectionRowBase{
		Certs:   []*x509.Certificate{certs.Chain3Cert},
		CertKey: certs.Chain3Key,
	}

	mockUpdater1 := certdeckmocks.NewMockCollectionUpdater(t)
	mockUpdater2 := certdeckmocks.NewMockCollectionUpdater(t)

	mockUpdater1.On("ID").Return("test-updater-1")
	mockUpdater2.On("ID").Return("test-updater-2")

	mockUpdater1.On("Retrieve").Return(testRow1, nil).Once()
	mockUpdater2.On("Retrieve").Return(testRow2, nil).Once()

	collection := certdeck.NewCollection(time.Second)

	data, err := collection.Get(mockUpdater1)
	require.NoError(t, err)
	require.Equal(t, testRow1, data)

	data, err = collection.Get(mockUpdater2)
	require.NoError(t, err)
	require.Equal(t, testRow2, data)

	t.Run("cache", func(t *testing.T) {
		mockUpdater1.On("Retrieve").Return(testRow3, nil).Once()

		// Data cached, updater not called.
		data, err = collection.Get(mockUpdater1)
		require.NoError(t, err)
		require.Equal(t, testRow1, data)

		time.Sleep(time.Second)

		// Data expired, updater called.
		data, err = collection.Get(mockUpdater1)
		require.NoError(t, err)
		require.Equal(t, testRow3, data)
	})

	mockUpdater1.AssertExpectations(t)
	mockUpdater2.AssertExpectations(t)
}
