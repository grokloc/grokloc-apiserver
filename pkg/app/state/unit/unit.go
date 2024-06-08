// Package unit manages state for the Unit environment.
package unit

import (
	"context"
	"log/slog"
	"os"
	"time"

	"github.com/google/uuid"
	"github.com/grokloc/grokloc-apiserver/pkg/app"
	"github.com/grokloc/grokloc-apiserver/pkg/app/admin/org"
	"github.com/grokloc/grokloc-apiserver/pkg/app/models"
	"github.com/grokloc/grokloc-apiserver/pkg/env"
	"github.com/grokloc/grokloc-apiserver/pkg/safe"
	"github.com/grokloc/grokloc-apiserver/pkg/security"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/matthewhartstonge/argon2"
)

// KnownKeyID will be set as a key version, not current.
// This value was chosen randomly.
const KnownKeyID = "c4d98d26-e6d4-4e75-b88b-dfbe8361757a"

// State returns a app.State instance for the Unit environment.
func State() (*app.State, error) {
	logger := slog.New(slog.NewJSONHandler(
		os.Stderr,
		&slog.HandlerOptions{AddSource: true, Level: slog.LevelError},
	))

	dbUrl, dbUrlOK := os.LookupEnv(app.PostgresAppUrlEnvKey)
	if !dbUrlOK {
		return nil, app.ErrorEnvVar
	}

	_, dbUrlParseErr := pgconn.ParseConfig(dbUrl)
	if dbUrlParseErr != nil {
		return nil, app.ErrorEnvVar
	}

	ctx := context.Background()

	master, poolErr := pgxpool.New(ctx, dbUrl)
	if poolErr != nil {
		return nil, poolErr
	}

	replicas := make([]*pgxpool.Pool, 1)
	replicas[0] = master // only a single db in Unit env

	argon2Config := argon2.DefaultConfig()
	argon2Config.TimeCost = 1 // ok for unit tests

	repositoryBase, repositoryBaseOK := os.LookupEnv(app.RepositoryBaseEnvKey)
	if !repositoryBaseOK {
		return nil, app.ErrorEnvVar
	}
	_, repositoryBaseErr := os.Stat(repositoryBase)
	if repositoryBaseErr != nil {
		return nil, repositoryBaseErr
	}

	signingKey := security.RandKey()

	keyMap := make(security.KeyMap)
	current := uuid.New()
	keyMap[current] = security.RandKey()
	keyMap[uuid.New()] = security.RandKey()                 // some "other" key
	keyMap[uuid.MustParse(KnownKeyID)] = security.RandKey() // "other" key with known ID

	versionKey, vkErr := security.NewVersionKey(keyMap, current)
	if vkErr != nil {
		return nil, vkErr
	}

	// create metadata for a root user and org
	orgName := safe.TrustedVarChar(security.RandString())
	ownerDisplayName := safe.TrustedVarChar(security.RandString())
	ownerEmail := safe.TrustedVarChar(security.RandString())
	ownerPassword, ownerPasswordErr := security.DerivePassword(security.RandString(), argon2Config)
	if ownerPasswordErr != nil {
		return nil, ownerPasswordErr
	}

	// insert root org and owner (root user) into db
	conn, connErr := master.Acquire(context.Background())
	if connErr != nil {
		return nil, connErr
	}
	defer conn.Release()

	o, owner, orgCreateErr := org.Create(context.Background(),
		conn.Conn(),
		orgName,
		ownerDisplayName,
		ownerEmail,
		*ownerPassword,
		models.RoleTest,
		versionKey)
	if orgCreateErr != nil {
		return nil, orgCreateErr
	}

	return &app.State{
		Level:          env.Unit,
		Logger:         logger,
		APIVersion:     "v0",
		Master:         master,
		Replicas:       replicas,
		ConnTimeout:    time.Duration(1000 * time.Millisecond),
		ExecTimeout:    time.Duration(1000 * time.Millisecond),
		Argon2Config:   argon2Config,
		RepositoryBase: repositoryBase,
		SigningKey:     signingKey,
		VersionKey:     versionKey,
		DefaultRole:    models.RoleTest,
		Root:           owner,
		Org:            o,
	}, nil
}
