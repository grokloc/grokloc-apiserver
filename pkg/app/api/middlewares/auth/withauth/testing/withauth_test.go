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
	"github.com/grokloc/grokloc-apiserver/pkg/app/admin/org"
	"github.com/grokloc/grokloc-apiserver/pkg/app/admin/user"
	"github.com/grokloc/grokloc-apiserver/pkg/app/api/handlers/token"
	"github.com/grokloc/grokloc-apiserver/pkg/app/api/middlewares/auth/withauth"
	"github.com/grokloc/grokloc-apiserver/pkg/app/api/middlewares/auth/withuser"
	"github.com/grokloc/grokloc-apiserver/pkg/app/api/middlewares/request"
	"github.com/grokloc/grokloc-apiserver/pkg/app/api/middlewares/withmodel"
	"github.com/grokloc/grokloc-apiserver/pkg/app/jwt"
	"github.com/grokloc/grokloc-apiserver/pkg/app/models"
	"github.com/grokloc/grokloc-apiserver/pkg/safe"
	"github.com/grokloc/grokloc-apiserver/pkg/security"

	"github.com/grokloc/grokloc-apiserver/pkg/app/state/unit"
	app_testing "github.com/grokloc/grokloc-apiserver/pkg/app/testing"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

type WithAuthSuite struct {
	suite.Suite
	c                                          http.Client
	o                                          *org.Org
	owner, regularUser, peerUser               *user.User
	srv                                        *httptest.Server
	st                                         *app.State
	tok, ownerTok, regularUserTok, peerUserTok token.JSONToken
}

func (s *WithAuthSuite) SetupSuite() {
	st, stErr := unit.State()
	require.NoError(s.T(), stErr)
	s.st = st
	s.c = http.Client{}

	rtr := chi.NewRouter()
	rtr.Use(request.Middleware(st))
	rtr.Use(withuser.Middleware(st))
	rtr.Route("/token", func(rtr chi.Router) {
		rtr.Post("/", token.Post(st))
	})
	rtr.Route("/root", func(rtr chi.Router) {
		rtr.Use(withauth.RequireOneOf(st, withuser.AuthRoot))
		rtr.Get("/", func(w http.ResponseWriter, r *http.Request) {})
	})
	rtr.Route("/org", func(rtr chi.Router) {
		rtr.Route("/{id}", func(rtr chi.Router) {
			rtr.Use(withmodel.Middleware(st, models.KindOrg))
			rtr.Use(withauth.RequireOneOf(st, withuser.AuthRoot, withuser.AuthOrg))
			rtr.Get("/", func(w http.ResponseWriter, r *http.Request) {})
		})
	})
	rtr.Route("/user", func(rtr chi.Router) {
		rtr.Route("/{id}", func(rtr chi.Router) {
			rtr.Use(withmodel.Middleware(st, models.KindUser))
			rtr.Use(withauth.RequireOneOf(st, withuser.AuthRoot, withuser.AuthOrg, withuser.AuthUser))
			rtr.Get("/", func(w http.ResponseWriter, r *http.Request) {})
		})
	})
	rtr.Route("/peer", func(rtr chi.Router) {
		rtr.Route("/{id}", func(rtr chi.Router) {
			rtr.Use(withmodel.Middleware(st, models.KindUser))
			rtr.Use(withauth.RequireOneOf(st, withuser.AuthRoot, withuser.AuthOrg, withuser.AuthUser, withuser.AuthPeer))
			rtr.Get("/", func(w http.ResponseWriter, r *http.Request) {})
		})
	})

	s.srv = httptest.NewServer(rtr)

	conn, connErr := s.st.Master.Acquire(context.Background())
	require.NoError(s.T(), connErr)
	defer conn.Release()
	var createErr error
	s.o, s.owner, s.regularUser, createErr = app_testing.TestOrgAndUser(conn.Conn(), s.st)
	require.NoError(s.T(), createErr)

	displayName := safe.TrustedVarChar(security.RandString())
	email := safe.TrustedVarChar(security.RandString())
	password, passwordErr := security.DerivePassword(security.RandString(), s.st.Argon2Config)
	require.NoError(s.T(), passwordErr)
	s.peerUser, createErr = user.Create(context.Background(), conn.Conn(), displayName, email, s.o.ID, *password, st.VersionKey)
	require.NoError(s.T(), createErr)
	require.NoError(s.T(), s.peerUser.UpdateStatus(context.Background(), conn.Conn(), st.VersionKey, models.StatusActive))

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

	tokenRequest = jwt.EncodeTokenRequest(s.peerUser.ID, s.peerUser.APISecret.String())
	req = http.Request{
		URL:    u,
		Method: http.MethodPost,
		Header: map[string][]string{
			app.IDHeader:           {s.peerUser.ID.String()},
			app.TokenRequestHeader: {tokenRequest},
		},
	}
	resp, postErr = s.c.Do(&req)
	require.NoError(s.T(), postErr)
	require.Equal(s.T(), http.StatusOK, resp.StatusCode)
	defer resp.Body.Close()
	body, readErr = io.ReadAll(resp.Body)
	require.NoError(s.T(), readErr)
	umErr = json.Unmarshal(body, &s.peerUserTok)
	require.NoError(s.T(), umErr)
	require.NotEmpty(s.T(), s.peerUserTok.Token)
}

func (s *WithAuthSuite) TestRootAuthAsRoot() {
	u, urlErr := url.Parse(s.srv.URL + "/root")
	require.NoError(s.T(), urlErr)
	req, reqErr := http.NewRequest(http.MethodGet, u.String(), nil)
	require.NoError(s.T(), reqErr)
	req.Header.Add(app.IDHeader, s.st.Root.ID.String())
	req.Header.Add(app.AuthorizationHeader, jwt.SignedStringToHeaderValue(s.tok.Token))
	resp, getErr := s.c.Do(req)
	require.NoError(s.T(), getErr)
	require.Equal(s.T(), http.StatusOK, resp.StatusCode)
}

func (s *WithAuthSuite) TestRootAuthAsOrgOwner() {
	u, urlErr := url.Parse(s.srv.URL + "/root")
	require.NoError(s.T(), urlErr)
	req, reqErr := http.NewRequest(http.MethodGet, u.String(), nil)
	require.NoError(s.T(), reqErr)
	req.Header.Add(app.IDHeader, s.owner.ID.String())
	req.Header.Add(app.AuthorizationHeader, jwt.SignedStringToHeaderValue(s.ownerTok.Token))
	resp, getErr := s.c.Do(req)
	require.NoError(s.T(), getErr)
	require.Equal(s.T(), http.StatusForbidden, resp.StatusCode)
}

func (s *WithAuthSuite) TestRootAuthAsRegularUser() {
	u, urlErr := url.Parse(s.srv.URL + "/root")
	require.NoError(s.T(), urlErr)
	req, reqErr := http.NewRequest(http.MethodGet, u.String(), nil)
	require.NoError(s.T(), reqErr)
	req.Header.Add(app.IDHeader, s.regularUser.ID.String())
	req.Header.Add(app.AuthorizationHeader, jwt.SignedStringToHeaderValue(s.regularUserTok.Token))
	resp, getErr := s.c.Do(req)
	require.NoError(s.T(), getErr)
	require.Equal(s.T(), http.StatusForbidden, resp.StatusCode)
}

func (s *WithAuthSuite) TestOrgAuthAsRoot() {
	u, urlErr := url.Parse(s.srv.URL + "/org/" + s.o.ID.String())
	require.NoError(s.T(), urlErr)
	req, reqErr := http.NewRequest(http.MethodGet, u.String(), nil)
	require.NoError(s.T(), reqErr)
	req.Header.Add(app.IDHeader, s.st.Root.ID.String())
	req.Header.Add(app.AuthorizationHeader, jwt.SignedStringToHeaderValue(s.tok.Token))
	resp, getErr := s.c.Do(req)
	require.NoError(s.T(), getErr)
	require.Equal(s.T(), http.StatusOK, resp.StatusCode)
}

func (s *WithAuthSuite) TestOrgAuthAsOrgOwner() {
	u, urlErr := url.Parse(s.srv.URL + "/org/" + s.o.ID.String())
	require.NoError(s.T(), urlErr)
	req, reqErr := http.NewRequest(http.MethodGet, u.String(), nil)
	require.NoError(s.T(), reqErr)
	req.Header.Add(app.IDHeader, s.owner.ID.String())
	req.Header.Add(app.AuthorizationHeader, jwt.SignedStringToHeaderValue(s.ownerTok.Token))
	resp, getErr := s.c.Do(req)
	require.NoError(s.T(), getErr)
	require.Equal(s.T(), http.StatusOK, resp.StatusCode)

	// try accessing a different org
	u, urlErr = url.Parse(s.srv.URL + "/org/" + s.st.Org.ID.String())
	require.NoError(s.T(), urlErr)
	req, reqErr = http.NewRequest(http.MethodGet, u.String(), nil)
	require.NoError(s.T(), reqErr)
	req.Header.Add(app.IDHeader, s.owner.ID.String())
	req.Header.Add(app.AuthorizationHeader, jwt.SignedStringToHeaderValue(s.ownerTok.Token))
	resp, getErr = s.c.Do(req)
	require.NoError(s.T(), getErr)
	require.Equal(s.T(), http.StatusForbidden, resp.StatusCode)
}

func (s *WithAuthSuite) TestOrgAuthAsRegularUser() {
	u, urlErr := url.Parse(s.srv.URL + "/org/" + s.o.ID.String())
	require.NoError(s.T(), urlErr)
	req, reqErr := http.NewRequest(http.MethodGet, u.String(), nil)
	require.NoError(s.T(), reqErr)
	req.Header.Add(app.IDHeader, s.regularUser.ID.String())
	req.Header.Add(app.AuthorizationHeader, jwt.SignedStringToHeaderValue(s.regularUserTok.Token))
	resp, getErr := s.c.Do(req)
	require.NoError(s.T(), getErr)
	require.Equal(s.T(), http.StatusForbidden, resp.StatusCode)
}

func (s *WithAuthSuite) TestUserAuthAsRoot() {
	u, urlErr := url.Parse(s.srv.URL + "/user/" + s.regularUser.ID.String())
	require.NoError(s.T(), urlErr)
	req, reqErr := http.NewRequest(http.MethodGet, u.String(), nil)
	require.NoError(s.T(), reqErr)
	req.Header.Add(app.IDHeader, s.st.Root.ID.String())
	req.Header.Add(app.AuthorizationHeader, jwt.SignedStringToHeaderValue(s.tok.Token))
	resp, getErr := s.c.Do(req)
	require.NoError(s.T(), getErr)
	require.Equal(s.T(), http.StatusOK, resp.StatusCode)
}

func (s *WithAuthSuite) TestUserAuthAsOrgOwner() {
	u, urlErr := url.Parse(s.srv.URL + "/user/" + s.regularUser.ID.String())
	require.NoError(s.T(), urlErr)
	req, reqErr := http.NewRequest(http.MethodGet, u.String(), nil)
	require.NoError(s.T(), reqErr)
	req.Header.Add(app.IDHeader, s.owner.ID.String())
	req.Header.Add(app.AuthorizationHeader, jwt.SignedStringToHeaderValue(s.ownerTok.Token))
	resp, getErr := s.c.Do(req)
	require.NoError(s.T(), getErr)
	require.Equal(s.T(), http.StatusOK, resp.StatusCode)

	// try a user in a different org
	u, urlErr = url.Parse(s.srv.URL + "/user/" + s.st.Root.ID.String())
	require.NoError(s.T(), urlErr)
	req, reqErr = http.NewRequest(http.MethodGet, u.String(), nil)
	require.NoError(s.T(), reqErr)
	req.Header.Add(app.IDHeader, s.owner.ID.String())
	req.Header.Add(app.AuthorizationHeader, jwt.SignedStringToHeaderValue(s.ownerTok.Token))
	resp, getErr = s.c.Do(req)
	require.NoError(s.T(), getErr)
	require.Equal(s.T(), http.StatusForbidden, resp.StatusCode)
}

func (s *WithAuthSuite) TestUserAuthAsRegularUser() {
	u, urlErr := url.Parse(s.srv.URL + "/user/" + s.regularUser.ID.String())
	require.NoError(s.T(), urlErr)
	req, reqErr := http.NewRequest(http.MethodGet, u.String(), nil)
	require.NoError(s.T(), reqErr)
	req.Header.Add(app.IDHeader, s.regularUser.ID.String())
	req.Header.Add(app.AuthorizationHeader, jwt.SignedStringToHeaderValue(s.regularUserTok.Token))
	resp, getErr := s.c.Do(req)
	require.NoError(s.T(), getErr)
	require.Equal(s.T(), http.StatusOK, resp.StatusCode)

	// try with a different user in user's org
	u, urlErr = url.Parse(s.srv.URL + "/user/" + s.peerUser.ID.String())
	require.NoError(s.T(), urlErr)
	req, reqErr = http.NewRequest(http.MethodGet, u.String(), nil)
	require.NoError(s.T(), reqErr)
	req.Header.Add(app.IDHeader, s.regularUser.ID.String())
	req.Header.Add(app.AuthorizationHeader, jwt.SignedStringToHeaderValue(s.regularUserTok.Token))
	resp, getErr = s.c.Do(req)
	require.NoError(s.T(), getErr)
	require.Equal(s.T(), http.StatusForbidden, resp.StatusCode)

	// try with a user in other org
	u, urlErr = url.Parse(s.srv.URL + "/user/" + s.st.Root.ID.String())
	require.NoError(s.T(), urlErr)
	req, reqErr = http.NewRequest(http.MethodGet, u.String(), nil)
	require.NoError(s.T(), reqErr)
	req.Header.Add(app.IDHeader, s.regularUser.ID.String())
	req.Header.Add(app.AuthorizationHeader, jwt.SignedStringToHeaderValue(s.regularUserTok.Token))
	resp, getErr = s.c.Do(req)
	require.NoError(s.T(), getErr)
	require.Equal(s.T(), http.StatusForbidden, resp.StatusCode)
}

func (s *WithAuthSuite) TestUserAuthAsPeerUser() {
	u, urlErr := url.Parse(s.srv.URL + "/peer/" + s.regularUser.ID.String())
	require.NoError(s.T(), urlErr)
	req, reqErr := http.NewRequest(http.MethodGet, u.String(), nil)
	require.NoError(s.T(), reqErr)
	req.Header.Add(app.IDHeader, s.peerUser.ID.String())
	req.Header.Add(app.AuthorizationHeader, jwt.SignedStringToHeaderValue(s.peerUserTok.Token))
	resp, getErr := s.c.Do(req)
	require.NoError(s.T(), getErr)
	require.Equal(s.T(), http.StatusOK, resp.StatusCode)

	// try with a user in other org
	u, urlErr = url.Parse(s.srv.URL + "/peer/" + s.st.Root.ID.String())
	require.NoError(s.T(), urlErr)
	req, reqErr = http.NewRequest(http.MethodGet, u.String(), nil)
	require.NoError(s.T(), reqErr)
	req.Header.Add(app.IDHeader, s.peerUser.ID.String())
	req.Header.Add(app.AuthorizationHeader, jwt.SignedStringToHeaderValue(s.peerUserTok.Token))
	resp, getErr = s.c.Do(req)
	require.NoError(s.T(), getErr)
	require.Equal(s.T(), http.StatusForbidden, resp.StatusCode)
}

func (s *WithAuthSuite) TearDownSuite() {
	s.srv.Close()
}

func TestWithAuthSuite(t *testing.T) {
	suite.Run(t, new(WithAuthSuite))
}
