package client

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/grokloc/grokloc-apiserver/pkg/app/api"
	"github.com/grokloc/grokloc-apiserver/pkg/app/state/unit"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

type ClientSuite struct {
	suite.Suite
	srv    *httptest.Server
	client *Client
}

func (s *ClientSuite) SetupSuite() {
	st, stErr := unit.State()
	require.NoError(s.T(), stErr)
	rtr := api.NewRouter(st)
	s.srv = httptest.NewServer(rtr)
	var clientErr error
	httpClient := http.Client{}
	s.client, clientErr = New(
		st.Root.ID.String(),
		st.Root.APISecret.String(),
		s.srv.URL,
		st.APIVersion,
		&httpClient,
	)
	require.NoError(s.T(), clientErr)
}

func (s *ClientSuite) TestOK() {
	require.NoError(s.T(), s.client.OK())
}

func (s *ClientSuite) TestAuthOK() {
	require.NoError(s.T(), s.client.AuthOK())
}

func (s *ClientSuite) TearDownSuite() {
	s.srv.Close()
}

func TestClientSuite(t *testing.T) {
	suite.Run(t, new(ClientSuite))
}
