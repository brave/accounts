package datastore

import (
	"errors"
	"fmt"
	"os"

	"github.com/brave-experiments/accounts/migrations"
	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	"github.com/golang-migrate/migrate/v4/source/iofs"
	"github.com/jackc/pgx/v5"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

const databaseURLEnv = "DATABASE_URL"

type Datastore struct {
	dbConfig *pgx.ConnConfig
	db       *gorm.DB
}

func NewDatastore() (*Datastore, error) {
	dbURL := os.Getenv(databaseURLEnv)
	if dbURL == "" {
		return nil, fmt.Errorf("DATABASE_URL environment variable not set")
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
	if err = migration.Up(); err != nil {
		if !errors.Is(err, migrate.ErrNoChange) {
			return nil, fmt.Errorf("Failed to run migrations: %w", err)
		}
		err = nil
	}

	db, err := gorm.Open(postgres.Open(dbURL), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	return &Datastore{dbConfig: dbConfig, db: db}, nil
}
