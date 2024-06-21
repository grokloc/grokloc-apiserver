package client

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/grokloc/grokloc-apiserver/pkg/app"
	"github.com/grokloc/grokloc-apiserver/pkg/app/admin/org"
	"github.com/grokloc/grokloc-apiserver/pkg/app/admin/user"
	"github.com/grokloc/grokloc-apiserver/pkg/app/api"
	"github.com/grokloc/grokloc-apiserver/pkg/app/state/unit"
	app_testing "github.com/grokloc/grokloc-apiserver/pkg/app/testing"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

type ClientSuite struct {
	suite.Suite
	srv                                           *httptest.Server
	st                                            *app.State
	org                                           *org.Org
	orgOwner, regularUser                         *user.User
	rootClient, orgOwnerClient, regularUserClient *Client
}

func (s *ClientSuite) SetupSuite() {
	st, stErr := unit.State()
	require.NoError(s.T(), stErr)
	s.st = st
	rtr := api.NewRouter(st)
	s.srv = httptest.NewServer(rtr)
	var clientErr error
	httpClient := http.Client{}

	s.rootClient, clientErr = New(
		st.Root.ID.String(),
		st.Root.APISecret.String(),
		s.srv.URL,
		st.APIVersion,
		&httpClient,
	)
	require.NoError(s.T(), clientErr)

	conn, connErr := st.Master.Acquire(context.Background())
	require.NoError(s.T(), connErr)
	defer conn.Release()
	o, orgOwner, regularUser, oErr := app_testing.TestOrgAndUser(conn.Conn(), st)
	require.NoError(s.T(), oErr)
	s.org = o
	s.orgOwner = orgOwner
	s.regularUser = regularUser

	s.orgOwnerClient, clientErr = New(
		orgOwner.ID.String(),
		orgOwner.APISecret.String(),
		s.srv.URL,
		st.APIVersion,
		&httpClient,
	)
	require.NoError(s.T(), clientErr)

	s.regularUserClient, clientErr = New(
		regularUser.ID.String(),
		regularUser.APISecret.String(),
		s.srv.URL,
		st.APIVersion,
		&httpClient,
	)
	require.NoError(s.T(), clientErr)
}

func (s *ClientSuite) TestOK() {
	require.NoError(s.T(), s.rootClient.OK())
	require.NoError(s.T(), s.orgOwnerClient.OK())
	require.NoError(s.T(), s.regularUserClient.OK())
}

func (s *ClientSuite) TestAuthOK() {
	require.NoError(s.T(), s.rootClient.AuthOK())
	require.NoError(s.T(), s.orgOwnerClient.OK())
	require.NoError(s.T(), s.regularUserClient.OK())
}

func (s *ClientSuite) TearDownSuite() {
	s.srv.Close()
}

func TestClientSuite(t *testing.T) {
	suite.Run(t, new(ClientSuite))
}
