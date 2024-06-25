package testing

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/grokloc/grokloc-apiserver/pkg/app"
	"github.com/grokloc/grokloc-apiserver/pkg/app/admin/user"
	"github.com/grokloc/grokloc-apiserver/pkg/app/api/handlers/token"
	"github.com/grokloc/grokloc-apiserver/pkg/app/api/middlewares/auth/withuser"
	"github.com/grokloc/grokloc-apiserver/pkg/app/api/middlewares/request"
	"github.com/grokloc/grokloc-apiserver/pkg/app/jwt"
	"github.com/grokloc/grokloc-apiserver/pkg/app/models"
	"github.com/grokloc/grokloc-apiserver/pkg/app/state/unit"
	app_testing "github.com/grokloc/grokloc-apiserver/pkg/app/testing"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

type TokenSuite struct {
	suite.Suite
	st   *app.State
	srv  *httptest.Server
	user *user.User
}

func (s *TokenSuite) SetupSuite() {
	st, stErr := unit.State()
	require.NoError(s.T(), stErr)
	s.st = st
	conn, connErr := s.st.Master.Acquire(context.Background())
	require.NoError(s.T(), connErr)
	_, owner, _, createErr := app_testing.TestOrgAndUser(conn.Conn(), s.st)
	s.user = owner
	require.NoError(s.T(), createErr)
	rtr := chi.NewRouter()
	rtr.Use(request.Middleware(st))
	rtr.Use(withuser.Middleware(st))
	rtr.Post("/", token.Post(st))
	s.srv = httptest.NewServer(rtr)
}

func (s *TokenSuite) TestToken() {
	u, urlErr := url.Parse(s.srv.URL + "/")
	require.NoError(s.T(), urlErr)
	tokenRequest := jwt.EncodeTokenRequest(s.user.ID, s.user.APISecret.String())
	req := http.Request{
		URL:    u,
		Method: http.MethodPost,
		Header: map[string][]string{
			app.IDHeader:           {s.user.ID.String()},
			app.TokenRequestHeader: {tokenRequest},
		},
	}
	client := http.Client{}
	resp, postErr := client.Do(&req)
	require.NoError(s.T(), postErr)
	require.Equal(s.T(), http.StatusOK, resp.StatusCode)
	defer resp.Body.Close()
	body, readErr := io.ReadAll(resp.Body)
	require.NoError(s.T(), readErr)
	var m token.JSONToken
	umErr := json.Unmarshal(body, &m)
	require.NoError(s.T(), umErr)
	require.NotEmpty(s.T(), m.Token)
	_, decodeErr := jwt.Decode(m.Token, s.st.SigningKey)
	require.NoError(s.T(), decodeErr)
}

func (s *TokenSuite) TestTokenMissingTokenRequest() {
	u, urlErr := url.Parse(s.srv.URL + "/")
	require.NoError(s.T(), urlErr)
	req := http.Request{
		URL:    u,
		Method: http.MethodPost,
		Header: map[string][]string{
			app.IDHeader: {s.user.ID.String()},
		},
	}
	client := http.Client{}
	resp, postErr := client.Do(&req)
	require.NoError(s.T(), postErr)
	require.Equal(s.T(), http.StatusBadRequest, resp.StatusCode)
}

func (s *TokenSuite) TestTokenBadTokenRequest() {
	u, urlErr := url.Parse(s.srv.URL + "/")
	require.NoError(s.T(), urlErr)
	// make new, random api secret that won't match
	tokenRequest := jwt.EncodeTokenRequest(s.user.ID, models.NewID().String())
	req := http.Request{
		URL:    u,
		Method: http.MethodPost,
		Header: map[string][]string{
			app.IDHeader:           {s.user.ID.String()},
			app.TokenRequestHeader: {tokenRequest},
		},
	}
	client := http.Client{}
	resp, postErr := client.Do(&req)
	require.NoError(s.T(), postErr)
	require.Equal(s.T(), http.StatusUnauthorized, resp.StatusCode)
}

func (s *TokenSuite) TearDownSuite() {
	s.srv.Close()
}

func TestTokenSuite(t *testing.T) {
	suite.Run(t, new(TokenSuite))
}
