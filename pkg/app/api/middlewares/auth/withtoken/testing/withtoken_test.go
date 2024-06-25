package testing

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/grokloc/grokloc-apiserver/pkg/app"
	"github.com/grokloc/grokloc-apiserver/pkg/app/admin/org"
	"github.com/grokloc/grokloc-apiserver/pkg/app/admin/user"
	"github.com/grokloc/grokloc-apiserver/pkg/app/api"
	"github.com/grokloc/grokloc-apiserver/pkg/app/api/handlers/token"
	"github.com/grokloc/grokloc-apiserver/pkg/app/jwt"

	go_jwt "github.com/golang-jwt/jwt/v5"
	"github.com/grokloc/grokloc-apiserver/pkg/app/state/unit"
	app_testing "github.com/grokloc/grokloc-apiserver/pkg/app/testing"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

type WithTokenSuite struct {
	suite.Suite
	c           http.Client
	st          *app.State
	srv         *httptest.Server
	org         *org.Org
	owner       *user.User
	regularUser *user.User
}

func (s *WithTokenSuite) SetupSuite() {
	st, stErr := unit.State()
	s.st = st
	require.NoError(s.T(), stErr)
	conn, connErr := s.st.Master.Acquire(context.Background())
	require.NoError(s.T(), connErr)
	defer conn.Release()

	var createErr error
	s.org, s.owner, s.regularUser, createErr = app_testing.TestOrgAndUser(conn.Conn(), s.st)
	require.NoError(s.T(), createErr)

	rtr := api.NewRouter(st)
	s.srv = httptest.NewServer(rtr)
	s.c = http.Client{}
}

func (s *WithTokenSuite) TestValidAuth() {
	tokenReqUrl, tokenReqUrlErr := url.Parse(s.srv.URL + "/token")
	require.NoError(s.T(), tokenReqUrlErr)
	regularUserTokenRequest := jwt.EncodeTokenRequest(s.regularUser.ID, s.regularUser.APISecret.String())
	regularUserReq := http.Request{
		URL:    tokenReqUrl,
		Method: http.MethodPost,
		Header: map[string][]string{
			app.IDHeader:           {s.regularUser.ID.String()},
			app.TokenRequestHeader: {regularUserTokenRequest},
		},
	}
	resp, postErr := s.c.Do(&regularUserReq)
	require.NoError(s.T(), postErr)
	require.Equal(s.T(), http.StatusOK, resp.StatusCode)
	defer resp.Body.Close()
	body, readErr := io.ReadAll(resp.Body)
	require.NoError(s.T(), readErr)
	var regularUserTok token.JSONToken
	umErr := json.Unmarshal(body, &regularUserTok)
	require.NoError(s.T(), umErr)
	require.NotEmpty(s.T(), regularUserTok.Token)

	u, urlErr := url.Parse(s.srv.URL + app.APIPath + s.st.APIVersion + "/ok")
	require.NoError(s.T(), urlErr)
	req, reqErr := http.NewRequest(http.MethodGet, u.String(), nil)
	require.NoError(s.T(), reqErr)
	req.Header.Add(app.IDHeader, s.regularUser.ID.String())
	req.Header.Add(app.AuthorizationHeader, jwt.SignedStringToHeaderValue(regularUserTok.Token))
	resp, getErr := s.c.Do(req)
	require.NoError(s.T(), getErr)
	require.Equal(s.T(), http.StatusOK, resp.StatusCode)
}

func (s *WithTokenSuite) TestMissingToken() {
	u, urlErr := url.Parse(s.srv.URL + app.APIPath + s.st.APIVersion + "/ok")
	require.NoError(s.T(), urlErr)
	req, reqErr := http.NewRequest(http.MethodGet, u.String(), nil)
	require.NoError(s.T(), reqErr)
	req.Header.Add(app.IDHeader, s.regularUser.ID.String())
	// token is missing
	resp, getErr := s.c.Do(req)
	require.NoError(s.T(), getErr)
	require.Equal(s.T(), http.StatusBadRequest, resp.StatusCode)
}

func (s *WithTokenSuite) TestWrongID() {
	tokenReqUrl, tokenReqUrlErr := url.Parse(s.srv.URL + "/token")
	require.NoError(s.T(), tokenReqUrlErr)
	regularUserTokenRequest := jwt.EncodeTokenRequest(s.regularUser.ID, s.regularUser.APISecret.String())
	regularUserReq := http.Request{
		URL:    tokenReqUrl,
		Method: http.MethodPost,
		Header: map[string][]string{
			app.IDHeader:           {s.regularUser.ID.String()},
			app.TokenRequestHeader: {regularUserTokenRequest},
		},
	}
	resp, postErr := s.c.Do(&regularUserReq)
	require.NoError(s.T(), postErr)
	require.Equal(s.T(), http.StatusOK, resp.StatusCode)
	defer resp.Body.Close()
	body, readErr := io.ReadAll(resp.Body)
	require.NoError(s.T(), readErr)
	var regularUserTok token.JSONToken
	umErr := json.Unmarshal(body, &regularUserTok)
	require.NoError(s.T(), umErr)
	require.NotEmpty(s.T(), regularUserTok.Token)

	u, urlErr := url.Parse(s.srv.URL + app.APIPath + s.st.APIVersion + "/ok")
	require.NoError(s.T(), urlErr)
	req, reqErr := http.NewRequest(http.MethodGet, u.String(), nil)
	require.NoError(s.T(), reqErr)
	req.Header.Add(app.IDHeader, s.owner.ID.String()) // should be regularUser
	req.Header.Add(app.AuthorizationHeader, jwt.SignedStringToHeaderValue(regularUserTok.Token))
	resp, getErr := s.c.Do(req)
	require.NoError(s.T(), getErr)
	require.Equal(s.T(), http.StatusUnauthorized, resp.StatusCode)
}

func (s *WithTokenSuite) TestWrongAPISecret() {
	tokenReqUrl, tokenReqUrlErr := url.Parse(s.srv.URL + "/token")
	require.NoError(s.T(), tokenReqUrlErr)
	regularUserTokenRequest := jwt.EncodeTokenRequest(s.regularUser.ID, s.regularUser.APISecret.String())
	regularUserReq := http.Request{
		URL:    tokenReqUrl,
		Method: http.MethodPost,
		Header: map[string][]string{
			app.IDHeader:           {s.regularUser.ID.String()},
			app.TokenRequestHeader: {regularUserTokenRequest},
		},
	}
	resp, postErr := s.c.Do(&regularUserReq)
	require.NoError(s.T(), postErr)
	require.Equal(s.T(), http.StatusOK, resp.StatusCode)
	defer resp.Body.Close()
	body, readErr := io.ReadAll(resp.Body)
	require.NoError(s.T(), readErr)
	var regularUserTok token.JSONToken
	umErr := json.Unmarshal(body, &regularUserTok)
	require.NoError(s.T(), umErr)
	require.NotEmpty(s.T(), regularUserTok.Token)

	// change regularUser's api secret, invalidating the token
	conn, connErr := s.st.Master.Acquire(context.Background())
	require.NoError(s.T(), connErr)
	defer conn.Release()
	// generate new, random api secret
	updateErr := s.regularUser.UpdateAPISecret(context.Background(), conn.Conn(), s.st.VersionKey)
	require.NoError(s.T(), updateErr)

	u, urlErr := url.Parse(s.srv.URL + app.APIPath + s.st.APIVersion + "/ok")
	require.NoError(s.T(), urlErr)
	req, reqErr := http.NewRequest(http.MethodGet, u.String(), nil)
	require.NoError(s.T(), reqErr)
	req.Header.Add(app.IDHeader, s.regularUser.ID.String())
	req.Header.Add(app.AuthorizationHeader, jwt.SignedStringToHeaderValue(regularUserTok.Token))
	resp, getErr := s.c.Do(req)
	require.NoError(s.T(), getErr)
	require.Equal(s.T(), http.StatusUnauthorized, resp.StatusCode)
}

func (s *WithTokenSuite) TestBadToken() {
	tokenReqUrl, tokenReqUrlErr := url.Parse(s.srv.URL + "/token")
	require.NoError(s.T(), tokenReqUrlErr)
	regularUserTokenRequest := jwt.EncodeTokenRequest(s.regularUser.ID, s.regularUser.APISecret.String())
	regularUserReq := http.Request{
		URL:    tokenReqUrl,
		Method: http.MethodPost,
		Header: map[string][]string{
			app.IDHeader:           {s.regularUser.ID.String()},
			app.TokenRequestHeader: {regularUserTokenRequest},
		},
	}
	resp, postErr := s.c.Do(&regularUserReq)
	require.NoError(s.T(), postErr)
	require.Equal(s.T(), http.StatusOK, resp.StatusCode)
	defer resp.Body.Close()
	body, readErr := io.ReadAll(resp.Body)
	require.NoError(s.T(), readErr)
	var regularUserTok token.JSONToken
	umErr := json.Unmarshal(body, &regularUserTok)
	require.NoError(s.T(), umErr)
	require.NotEmpty(s.T(), regularUserTok.Token)

	u, urlErr := url.Parse(s.srv.URL + app.APIPath + s.st.APIVersion + "/ok")
	require.NoError(s.T(), urlErr)
	req, reqErr := http.NewRequest(http.MethodGet, u.String(), nil)
	require.NoError(s.T(), reqErr)
	req.Header.Add(app.IDHeader, s.regularUser.ID.String())
	req.Header.Add(app.AuthorizationHeader, "not.a.token") // in place of token
	resp, getErr := s.c.Do(req)
	require.NoError(s.T(), getErr)
	require.Equal(s.T(), http.StatusBadRequest, resp.StatusCode)
}

func (s *WithTokenSuite) TestExpiredToken() {
	now := time.Now().Unix()
	tokenRequest := jwt.EncodeTokenRequest(s.regularUser.ID, s.regularUser.APISecret.String())
	tok := go_jwt.NewWithClaims(go_jwt.SigningMethodHS256, go_jwt.MapClaims{
		"iss": "GrokLOC.com",
		"sub": tokenRequest,
		"nbf": now,
		"iat": now,
		"exp": now - jwt.Expiration,
	})
	regularUserToken, tokenErr := tok.SignedString(s.st.SigningKey)
	require.NoError(s.T(), tokenErr)

	u, urlErr := url.Parse(s.srv.URL + app.APIPath + s.st.APIVersion + "/ok")
	require.NoError(s.T(), urlErr)
	req, reqErr := http.NewRequest(http.MethodGet, u.String(), nil)
	require.NoError(s.T(), reqErr)
	req.Header.Add(app.IDHeader, s.regularUser.ID.String())
	req.Header.Add(app.AuthorizationHeader, jwt.SignedStringToHeaderValue(regularUserToken))
	resp, getErr := s.c.Do(req)
	require.NoError(s.T(), getErr)
	require.Equal(s.T(), http.StatusBadRequest, resp.StatusCode)
}

func (s *WithTokenSuite) TearDownSuite() {
	s.srv.Close()
}

func TestWithTokenSuite(t *testing.T) {
	suite.Run(t, new(WithTokenSuite))
}
