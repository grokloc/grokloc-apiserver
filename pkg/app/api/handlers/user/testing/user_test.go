package testing

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/grokloc/grokloc-apiserver/pkg/app"

	"github.com/grokloc/grokloc-apiserver/pkg/app/admin/org"
	"github.com/grokloc/grokloc-apiserver/pkg/app/admin/user"
	"github.com/grokloc/grokloc-apiserver/pkg/app/api"
	"github.com/grokloc/grokloc-apiserver/pkg/app/api/handlers/token"
	"github.com/grokloc/grokloc-apiserver/pkg/app/jwt"
	"github.com/grokloc/grokloc-apiserver/pkg/app/state/unit"
	app_testing "github.com/grokloc/grokloc-apiserver/pkg/app/testing"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

type UserSuite struct {
	suite.Suite
	c                             http.Client
	o                             *org.Org
	owner, regularUser            *user.User
	srv                           *httptest.Server
	st                            *app.State
	tok, ownerTok, regularUserTok token.JSONToken
}

func (s *UserSuite) SetupSuite() {
	st, stErr := unit.State()
	require.NoError(s.T(), stErr)
	rtr := api.NewRouter(st)
	s.srv = httptest.NewServer(rtr)
	s.st = st
	s.c = http.Client{}

	conn, connErr := s.st.Master.Acquire(context.Background())
	require.NoError(s.T(), connErr)
	defer conn.Release()
	var createErr error
	s.o, s.owner, s.regularUser, createErr = app_testing.TestOrgAndUser(conn.Conn(), s.st)
	require.NoError(s.T(), createErr)

	u, urlErr := url.Parse(s.srv.URL + "/token")
	require.NoError(s.T(), urlErr)
	tokenRequest := jwt.EncodeTokenRequest(s.st.Root.ID, s.st.Root.APISecret.String())
	req := http.Request{
		URL:    u,
		Method: http.MethodPost,
		Header: map[string][]string{
			app.IDHeader:           {s.st.Root.ID.String()},
			app.TokenRequestHeader: {tokenRequest},
		},
	}
	resp, postErr := s.c.Do(&req)
	require.NoError(s.T(), postErr)
	require.Equal(s.T(), http.StatusOK, resp.StatusCode)
	defer resp.Body.Close()
	body, readErr := io.ReadAll(resp.Body)
	require.NoError(s.T(), readErr)
	umErr := json.Unmarshal(body, &s.tok)
	require.NoError(s.T(), umErr)
	require.NotEmpty(s.T(), s.tok.Token)

	tokenRequest = jwt.EncodeTokenRequest(s.owner.ID, s.owner.APISecret.String())
	req = http.Request{
		URL:    u,
		Method: http.MethodPost,
		Header: map[string][]string{
			app.IDHeader:           {s.owner.ID.String()},
			app.TokenRequestHeader: {tokenRequest},
		},
	}
	resp, postErr = s.c.Do(&req)
	require.NoError(s.T(), postErr)
	require.Equal(s.T(), http.StatusOK, resp.StatusCode)
	defer resp.Body.Close()
	body, readErr = io.ReadAll(resp.Body)
	require.NoError(s.T(), readErr)
	umErr = json.Unmarshal(body, &s.ownerTok)
	require.NoError(s.T(), umErr)
	require.NotEmpty(s.T(), s.ownerTok.Token)

	tokenRequest = jwt.EncodeTokenRequest(s.regularUser.ID, s.regularUser.APISecret.String())
	req = http.Request{
		URL:    u,
		Method: http.MethodPost,
		Header: map[string][]string{
			app.IDHeader:           {s.regularUser.ID.String()},
			app.TokenRequestHeader: {tokenRequest},
		},
	}
	resp, postErr = s.c.Do(&req)
	require.NoError(s.T(), postErr)
	require.Equal(s.T(), http.StatusOK, resp.StatusCode)
	defer resp.Body.Close()
	body, readErr = io.ReadAll(resp.Body)
	require.NoError(s.T(), readErr)
	umErr = json.Unmarshal(body, &s.regularUserTok)
	require.NoError(s.T(), umErr)
	require.NotEmpty(s.T(), s.regularUserTok.Token)
}

func (s *UserSuite) TearDownSuite() {
	s.srv.Close()
}

func TestUserSuite(t *testing.T) {
	suite.Run(t, new(UserSuite))
}
