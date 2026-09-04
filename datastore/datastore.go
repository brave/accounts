package datastore

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/brave/accounts/migrations"
	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	"github.com/golang-migrate/migrate/v4/source/iofs"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

const databaseURLEnv = "DATABASE_URL"
const keyServiceDatabaseURLEnv = "KEY_SERVICE_DATABASE_URL"
const testDatabaseURLEnv = "TEST_DATABASE_URL"
const testKeyServiceDatabaseURLEnv = "TEST_KEY_SERVICE_DATABASE_URL"
const defaultTestDatabaseURLEnv = "postgres://accounts:password@localhost:5435/test?sslmode=disable"
const defaultTestKeyServiceDatabaseURLEnv = "postgres://accounts:password@localhost:5435/keys_test?sslmode=disable"

const (
	databasePoolSizeEnv     = "DATABASE_POOL_SIZE"
	defaultDatabasePoolSize = 100
	databaseConnMaxLifetime = time.Hour
)

type Datastore struct {
	DB                *gorm.DB
	minSessionVersion int
}

func NewDatastore(minSessionVersion int, isKeyService bool, isTesting bool) (*Datastore, error) {
	var err error
	var rdsConnector *rdsConnector
	var envVar string
	if isTesting {
		if isKeyService {
			envVar = testKeyServiceDatabaseURLEnv
		} else {
			envVar = testDatabaseURLEnv
		}
	} else {
		if isKeyService {
			envVar = keyServiceDatabaseURLEnv
		} else {
			envVar = databaseURLEnv
		}
	}
	dbURL := os.Getenv(envVar)
	if dbURL == "" {
		if isTesting {
			if isKeyService {
				dbURL = defaultTestKeyServiceDatabaseURLEnv
			} else {
				dbURL = defaultTestDatabaseURLEnv
			}
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

	iofsDriver, err := iofs.New(migrations.MigrationFiles, ".")
	if err != nil {
		return nil, fmt.Errorf("failed to load iofs driver for migrations: %w", err)
	}

	migration, err := migrate.NewWithSourceInstance(
		"iofs",
		iofsDriver,
		dbURL,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to init migrations: %w", err)
	}

	if isTesting {
		if err = migration.Drop(); err != nil {
			return nil, fmt.Errorf("failed to down migrations for testing: %w", err)
		}
		migration.Close() //nolint:errcheck
		migration, err = migrate.NewWithSourceInstance(
			"iofs",
			iofsDriver,
			dbURL,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to re-init migrations: %w", err)
		}
	}

	if err = migration.Up(); err != nil {
		if !errors.Is(err, migrate.ErrNoChange) {
			return nil, fmt.Errorf("failed to run migrations: %w", err)
		}
	}
	migration.Close() //nolint:errcheck

	pgConfig := postgres.Config{
		DSN: dbURL,
	}

	if !isTesting && rdsConnector != nil {
		pgxConfig, err := pgx.ParseConfig(dbURL)
		if err != nil {
			return nil, err
		}

		baseDB := stdlib.OpenDB(*pgxConfig, stdlib.OptionBeforeConnect(rdsConnector.updateConnConfig))
		pgConfig.Conn = baseDB
	}
	db, err := gorm.Open(postgres.New(pgConfig), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	if err = configureDBPool(db); err != nil {
		return nil, err
	}

	return &Datastore{
		DB:                db,
		minSessionVersion: minSessionVersion,
	}, nil
}

func parseDatabasePoolSize() (int, error) {
	size := defaultDatabasePoolSize
	if raw := os.Getenv(databasePoolSizeEnv); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed <= 0 {
			return 0, fmt.Errorf("invalid %s: %q", databasePoolSizeEnv, raw)
		}
		size = parsed
	}
	return size, nil
}

func configureDBPool(db *gorm.DB) error {
	poolSize, err := parseDatabasePoolSize()
	if err != nil {
		return err
	}

	sqlDB, err := db.DB()
	if err != nil {
		return fmt.Errorf("failed to get database pool: %w", err)
	}

	// Keep max idle equal to max open so the pool does not close connections
	// under load (Go's default max idle is 2, which churns RDS IAM auth).
	sqlDB.SetMaxOpenConns(poolSize)
	sqlDB.SetMaxIdleConns(poolSize)
	sqlDB.SetConnMaxLifetime(databaseConnMaxLifetime)

	log.Info().Msgf("database pool size: %d", poolSize)
	return nil
}

func (ds *Datastore) Close() {
	db, err := ds.DB.DB()
	if err != nil {
		panic("failed to get DB for closing")
	}
	conn, err := db.Conn(context.Background())
	if err != nil {
		panic("failed to get DB connection for closing")
	}
	if conn.Close() != nil {
		panic("failed to close DB connection")
	}
	if err := db.Close(); err != nil {
		panic("failed to close DB")
	}
	ds.DB = nil
}
