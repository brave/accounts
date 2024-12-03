package migrations

import "embed"

//go:embed *
var MigrationFilesWithExtension embed.FS

//go:embed 20*
var MigrationFiles embed.FS
