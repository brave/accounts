package controllers_test

import (
	"testing"

	"github.com/brave/accounts/controllers"
	"github.com/brave/accounts/datastore"
	"github.com/brave/accounts/middleware"
	"github.com/brave/accounts/services"
	"github.com/brave/accounts/util"
	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/require"
)

func initKeyServiceForTest(t *testing.T, keyServiceDs **datastore.Datastore, ds *datastore.Datastore) {
	t.Setenv("KEY_SERVICE_URL", "http://localhost:8080")
	t.Setenv("KEY_SERVICE_SECRET", "abc123")
	var err error
	*keyServiceDs, err = datastore.NewDatastore(datastore.EmailAuthSessionVersion, true, true)
	require.NoError(t, err)
	_, err = (*keyServiceDs).GetOrCreateJWTKeys(true, true)
	require.NoError(t, err)

	var jwtKey datastore.JWTKey
	require.NoError(t, (*keyServiceDs).DB.First(&jwtKey).Error)
	require.NoError(t, ds.DB.Create(&datastore.JWTKey{
		PublicKey: jwtKey.PublicKey,
	}).Error)

	keyServiceJwtService, err := services.NewJWTService(*keyServiceDs, true)
	require.NoError(t, err)
	keyServiceOpaqueService, err := services.NewOpaqueService(*keyServiceDs, true)
	require.NoError(t, err)
	serverKeysController := controllers.NewServerKeysController(keyServiceOpaqueService, keyServiceJwtService)

	util.TestKeyServiceRouter = chi.NewRouter()
	util.TestKeyServiceRouter.Mount("/v2/server_keys", serverKeysController.Router(middleware.KeyServiceMiddleware()))
}
