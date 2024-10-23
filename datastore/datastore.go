package datastore

import (
	"fmt"
	"os"

	"github.com/jackc/pgx/v5"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
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

	db, err := gorm.Open(postgres.Open(dbURL), &gorm.Config{})
	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	return &Datastore{dbConfig: dbConfig, db: db}, nil
}
