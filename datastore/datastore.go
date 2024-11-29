package datastore

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/brave/accounts/migrations"
	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	"github.com/golang-migrate/migrate/v4/source/iofs"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/rs/zerolog/log"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

const databaseURLEnv = "DATABASE_URL"
const testDatabaseURLEnv = "TEST_DATABASE_URL"
const defaultTestDatabaseURLEnv = "postgres://accounts:password@localhost:5435/test?sslmode=disable"

type Datastore struct {
	listenPool                   *pgxpool.Pool
	DB                           *gorm.DB
	minSessionVersion            int
	webhookUrls                  map[string]interface{}
	verificationEventWaitMap     map[uuid.UUID]*verificationWaitRequest
	verificationEventWaitMapLock sync.Mutex
}

func NewDatastore(minSessionVersion int, isTesting bool) (*Datastore, error) {
	var err error
	var rdsConnector *rdsConnector
	envVar := databaseURLEnv
	if isTesting {
		envVar = testDatabaseURLEnv
	}
	dbURL := os.Getenv(envVar)
	if dbURL == "" {
		if isTesting {
			dbURL = defaultTestDatabaseURLEnv
		} else if os.Getenv(rdsHostKey) != "" {
			rdsConnector = newRDSConnector()
			dbURL, err = rdsConnector.getConnectionString(context.Background())
			if err != nil {
				return nil, err
			}
		} else {
			return nil, fmt.Errorf("%v environment variable not set", envVar)
		}
	}

	var files embed.FS
	if isTesting {
		files = migrations.MigrationFiles
	} else {
		files = migrations.MigrationFilesWithExtension
	}

	iofsDriver, err := iofs.New(files, ".")
	if err != nil {
		return nil, fmt.Errorf("failed to load iofs driver for migrations: %w", err)
	}

	migration, err := migrate.NewWithSourceInstance(
		"iofs",
		iofsDriver,
		dbURL,
	)
	if err != nil {
		return nil, fmt.Errorf("Failed to init migrations: %w", err)
	}

	if isTesting {
		if err = migration.Drop(); err != nil {
			return nil, fmt.Errorf("failed to down migrations for testing: %w", err)
		}
		migration, err = migrate.NewWithSourceInstance(
			"iofs",
			iofsDriver,
			dbURL,
		)
		if err != nil {
			return nil, fmt.Errorf("Failed to re-init migrations: %w", err)
		}
	}

	if err = migration.Up(); err != nil {
		if !errors.Is(err, migrate.ErrNoChange) {
			return nil, fmt.Errorf("Failed to run migrations: %w", err)
		}
	}

	pgConfig := postgres.Config{
		DSN: dbURL,
	}
	listenPoolConfig, err := pgxpool.ParseConfig(dbURL)
	listenPoolConfig.AfterRelease = func(c *pgx.Conn) bool {
		_, err := c.Exec(context.Background(), "UNLISTEN *")
		if err != nil {
			log.Error().Msgf("error unlistening channels on conn release: %v", err)
			return false
		}
		return true
	}

	if err != nil {
		return nil, fmt.Errorf("error parsing database connection config: %w", err)
	}
	if rdsConnector != nil {
		pgxConfig, err := pgx.ParseConfig(dbURL)
		if err != nil {
			return nil, err
		}
		listenPoolConfig.BeforeConnect = rdsConnector.updateConnConfig

		baseDB := stdlib.OpenDB(*pgxConfig, stdlib.OptionBeforeConnect(rdsConnector.updateConnConfig))
		pgConfig.Conn = baseDB
	}
	db, err := gorm.Open(postgres.New(pgConfig), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	listenPool, err := pgxpool.NewWithConfig(context.Background(), listenPoolConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	webhookUrls := make(map[string]interface{})

	// Parse webhook URLs from environment variable
	if urls := os.Getenv(WebhookKeysEnv); urls != "" {
		pairs := strings.Split(urls, ",")
		for _, pair := range pairs {
			if parts := strings.Split(pair, "="); len(parts) == 2 {
				webhookUrls[parts[0]] = true
			}
		}
	}

	return &Datastore{
		listenPool:        listenPool,
		DB:                db,
		minSessionVersion: minSessionVersion,
		webhookUrls:       webhookUrls,
	}, nil
}

func (ds *Datastore) Close() {
	ds.listenPool.Close()
	ds.DB.ConnPool.(*sql.DB).Close()
}
