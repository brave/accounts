package datastore

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/brave-experiments/accounts/migrations"
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
const testDatabaseURLEnv = "TEST_DATABASE_URL"
const defaultTestDatabaseURLEnv = "postgres://accounts:password@localhost:5435/test?sslmode=disable"

type Datastore struct {
	dbConfig          *pgx.ConnConfig
	DB                *gorm.DB
	minSessionVersion int
	webhookUrls       map[string]interface{}
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

	dbConfig, err := pgx.ParseConfig(dbURL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse databse url")
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
	if rdsConnector != nil {
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

	return &Datastore{dbConfig, db, minSessionVersion, webhookUrls}, nil
}
