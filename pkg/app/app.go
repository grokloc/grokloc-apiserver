package app

import (
	"errors"
	"fmt"
)

const (
	PostgresAppUrlEnvKey = "POSTGRES_APP_URL"
	RepositoryBaseEnvKey = "REPOSITORY_BASE"
	AuthorizationHeader  = "authorization"
	IDHeader             = "x-grokloc-id"
	TokenRequestHeader   = "x-grokloc-token-request"
	MaxBodySize          = 8192
	APIPath              = "/api/"
)

var ErrorEnvVar = errors.New("missing or malformed environment variable")

var ErrorInadequateAuthorization = errors.New("inadequate authorization provided")

var ErrorBody = fmt.Errorf("body malformed or exceeds %v bytes", MaxBodySize)
