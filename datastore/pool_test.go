package datastore

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseDatabasePoolSize(t *testing.T) {
	t.Run("default", func(t *testing.T) {
		t.Setenv(databasePoolSizeEnv, "")
		size, err := parseDatabasePoolSize()
		require.NoError(t, err)
		require.Equal(t, defaultDatabasePoolSize, size)
	})

	t.Run("custom", func(t *testing.T) {
		t.Setenv(databasePoolSizeEnv, "200")
		size, err := parseDatabasePoolSize()
		require.NoError(t, err)
		require.Equal(t, 200, size)
	})

	t.Run("invalid", func(t *testing.T) {
		t.Setenv(databasePoolSizeEnv, "nope")
		_, err := parseDatabasePoolSize()
		require.Error(t, err)
	})

	t.Run("non-positive", func(t *testing.T) {
		t.Setenv(databasePoolSizeEnv, "0")
		_, err := parseDatabasePoolSize()
		require.Error(t, err)
	})
}
