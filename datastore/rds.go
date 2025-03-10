package datastore

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/feature/rds/auth"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/jackc/pgx/v5"
)

const defaultRegion = "us-west-2"

const (
	rdsRoleKey   = "RDS_ROLE"
	rdsPortKey   = "RDS_DATABASE_PORT"
	rdsHostKey   = "RDS_WRITER_ENDPOINT"
	rdsUserKey   = "RDS_USER"
	rdsDbNameKey = "RDS_DATABASE_NAME"
	regionKey    = "AWS_REGION"
)

type rdsConnector struct {
	hostAndPort    string
	dbName         string
	user           string
	token          string
	region         string
	role           string
	tokenCacheTime time.Time
	mu             sync.Mutex
}

func newRDSConnector() *rdsConnector {
	port := os.Getenv(rdsPortKey)
	host := os.Getenv(rdsHostKey)
	user := os.Getenv(rdsUserKey)
	dbName := os.Getenv(rdsDbNameKey)
	region := os.Getenv(regionKey)
	role := os.Getenv(rdsRoleKey)

	if region == "" {
		region = defaultRegion
	}
	hostAndPort := fmt.Sprintf("%s:%s", host, port)
	return &rdsConnector{
		hostAndPort: hostAndPort,
		dbName:      dbName,
		user:        user,
		region:      region,
		role:        role,
	}
}

func (c *rdsConnector) getAuthToken(ctx context.Context) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if time.Since(c.tokenCacheTime) > 10*time.Minute {
		cfg, err := config.LoadDefaultConfig(ctx)
		if err != nil {
			return "", fmt.Errorf("failed to load AWS config")
		}
		// Create STS client and assume role
		stsClient := sts.NewFromConfig(cfg)
		roleProvider := stscreds.NewAssumeRoleProvider(stsClient, c.role)
		cfgWithRole, err := config.LoadDefaultConfig(ctx,
			config.WithCredentialsProvider(roleProvider))
		if err != nil {
			return "", fmt.Errorf("failed to assume role: %w", err)
		}

		token, err := auth.BuildAuthToken(
			ctx, c.hostAndPort, c.region, c.user, cfgWithRole.Credentials)
		if err != nil {
			return "", fmt.Errorf("failed to create authentication token: %w", err)
		}
		c.token = token
		c.tokenCacheTime = time.Now()
	}
	return c.token, nil
}

func (c *rdsConnector) getConnectionString(ctx context.Context) (string, error) {
	token, err := c.getAuthToken(ctx)
	if err != nil {
		return "", err
	}

	return fmt.Sprintf("postgres://%s:%s@%s/%s?sslmode=require", c.user, url.QueryEscape(token), c.hostAndPort, c.dbName), nil
}

func (c *rdsConnector) updateConnConfig(ctx context.Context, config *pgx.ConnConfig) error {
	token, err := c.getAuthToken(ctx)
	if err != nil {
		return err
	}
	config.Password = token

	return nil
}
