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
	"github.com/grokloc/grokloc-apiserver/pkg/app/state/unit"
	app_testing "github.com/grokloc/grokloc-apiserver/pkg/app/testing"
	"github.com/grokloc/grokloc-apiserver/pkg/safe"
	"github.com/grokloc/grokloc-apiserver/pkg/security"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

type WithAuthSuite struct {
	suite.Suite
	st                               *app.State
	srv                              *httptest.Server
	org, otherOrg                    *org.Org
	owner, otherOrgOwner             *user.User
	regularUser, otherOrgRegularUser *user.User
	peerRegularUser                  *user.User
	tok                              token.JSONToken
	c                                *http.Client
}

func (s *WithAuthSuite) SetupSuite() {
	st, stErr := unit.State()
	require.NoError(s.T(), stErr)
	s.st = st
	conn, connErr := s.st.Master.Acquire(context.Background())
	require.NoError(s.T(), connErr)
	defer conn.Release()

	var createErr error
	s.org, s.owner, s.regularUser, createErr = app_testing.TestOrgAndUser(conn.Conn(), s.st)
	require.NoError(s.T(), createErr)
	s.otherOrg, s.otherOrgOwner, s.otherOrgRegularUser, createErr = app_testing.TestOrgAndUser(conn.Conn(), s.st)
	require.NoError(s.T(), createErr)

	// additional user in org, a teammate
	password, passwordErr := security.DerivePassword(security.RandString(), s.st.Argon2Config)
	require.NoError(s.T(), passwordErr)
	s.peerRegularUser, createErr = user.Create(
		context.Background(),
		conn.Conn(),
		safe.TrustedVarChar(security.RandString()),
		safe.TrustedVarChar(security.RandString()),
		s.org.ID,
		*password,
		s.st.VersionKey,
	)
	require.NoError(s.T(), createErr)
	require.NoError(s.T(), s.peerRegularUser.UpdateStatus(context.Background(), conn.Conn(), st.VersionKey, models.StatusActive))

	s.c = &http.Client{}

	rtr := chi.NewRouter()
	rtr.Use(request.Middleware(st))
	rtr.Use(withuser.Middleware(st))

	rtr.Post("/token", token.Post(st))

	rtr.With(withauth.RequireOneOf(withuser.AuthRoot)).
		Get("/root", func(w http.ResponseWriter, r *http.Request) {})

	rtr.Route("/org", func(rtr chi.Router) {
		rtr.Route("/{id}", func(rtr chi.Router) {
			rtr.Use(withmodel.Middleware(st, models.KindOrg))
			rtr.Use(withauth.RequireOneOf(withuser.AuthOrg))
			rtr.Get("/", func(w http.ResponseWriter, r *http.Request) {
				_ = withmodel.GetModelWithID(r)
				_ = withmodel.GetModelWithOrg(r)
			})
		})
	})

	rtr.Route("/user", func(rtr chi.Router) {
		rtr.Route("/{id}", func(rtr chi.Router) {
			rtr.Use(withmodel.Middleware(st, models.KindUser))
			rtr.Use(withauth.RequireOneOf(withuser.AuthUser))
			rtr.Get("/", func(w http.ResponseWriter, r *http.Request) {
				_ = withmodel.GetModelWithID(r)
			})
		})
	})

	// this lets users in the same org access each other
	rtr.Route("/peer", func(rtr chi.Router) {
		rtr.Route("/{id}", func(rtr chi.Router) {
			rtr.Use(withmodel.Middleware(st, models.KindUser))
			rtr.Use(withauth.RequireOneOf(withuser.AuthPeer))
			rtr.Get("/", func(w http.ResponseWriter, r *http.Request) {
				_ = withmodel.GetModelWithID(r)
			})
		})
	})

	s.srv = httptest.NewServer(rtr)

	// get root token
	u, urlErr := url.Parse(s.srv.URL + "/token")
	require.NoError(s.T(), urlErr)
	tokenRequest := jwt.EncodeTokenRequest(s.st.Root.ID, s.st.Root.APISecret.String())
	req0 := http.Request{
		URL:    u,
		Method: http.MethodPost,
		Header: map[string][]string{
			app.IDHeader:           {s.st.Root.ID.String()},
			app.TokenRequestHeader: {tokenRequest},
		},
	}
	resp, postErr := s.c.Do(&req0)
	require.NoError(s.T(), postErr)
	defer resp.Body.Close()
	body, readErr := io.ReadAll(resp.Body)
	require.NoError(s.T(), readErr)
	umErr := json.Unmarshal(body, &s.tok)
	require.NoError(s.T(), umErr)
	require.NotEmpty(s.T(), s.tok.Token)
}

func (s *WithAuthSuite) TestAuthRootAsRoot() {
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

func (s *WithAuthSuite) TestAuthRootAsOrgOwner() {
	tokenUrl, tokenUrlErr := url.Parse(s.srv.URL + "/token")
	require.NoError(s.T(), tokenUrlErr)
	tokenRequestValue := jwt.EncodeTokenRequest(s.owner.ID, s.owner.APISecret.String())
	tokenReq := http.Request{
		URL:    tokenUrl,
		Method: http.MethodPost,
		Header: map[string][]string{
			app.IDHeader:           {s.owner.ID.String()},
			app.TokenRequestHeader: {tokenRequestValue},
		},
	}
	resp, postErr := s.c.Do(&tokenReq)
	require.NoError(s.T(), postErr)
	require.Equal(s.T(), http.StatusOK, resp.StatusCode)
	defer resp.Body.Close()
	body, readErr := io.ReadAll(resp.Body)
	require.NoError(s.T(), readErr)
	var ownerTok token.JSONToken
	umErr := json.Unmarshal(body, &ownerTok)
	require.NoError(s.T(), umErr)
	u, urlErr := url.Parse(s.srv.URL + "/root")
	require.NoError(s.T(), urlErr)
	req, reqErr := http.NewRequest(http.MethodGet, u.String(), nil)
	require.NoError(s.T(), reqErr)
	req.Header.Add(app.IDHeader, s.owner.ID.String())
	req.Header.Add(app.AuthorizationHeader, jwt.SignedStringToHeaderValue(ownerTok.Token))
	resp, getErr := s.c.Do(req)
	require.NoError(s.T(), getErr)
	require.Equal(s.T(), http.StatusForbidden, resp.StatusCode)
}

func (s *WithAuthSuite) TestAuthRootAsRegularUser() {
	tokenUrl, tokenUrlErr := url.Parse(s.srv.URL + "/token")
	require.NoError(s.T(), tokenUrlErr)
	tokenRequestValue := jwt.EncodeTokenRequest(s.regularUser.ID, s.regularUser.APISecret.String())
	tokenReq := http.Request{
		URL:    tokenUrl,
		Method: http.MethodPost,
		Header: map[string][]string{
			app.IDHeader:           {s.regularUser.ID.String()},
			app.TokenRequestHeader: {tokenRequestValue},
		},
	}
	resp, postErr := s.c.Do(&tokenReq)
	require.NoError(s.T(), postErr)
	require.Equal(s.T(), http.StatusOK, resp.StatusCode)
	defer resp.Body.Close()
	body, readErr := io.ReadAll(resp.Body)
	require.NoError(s.T(), readErr)
	var ownerTok token.JSONToken
	umErr := json.Unmarshal(body, &ownerTok)
	require.NoError(s.T(), umErr)
	u, urlErr := url.Parse(s.srv.URL + "/root")
	require.NoError(s.T(), urlErr)
	req, reqErr := http.NewRequest(http.MethodGet, u.String(), nil)
	require.NoError(s.T(), reqErr)
	req.Header.Add(app.IDHeader, s.regularUser.ID.String())
	req.Header.Add(app.AuthorizationHeader, jwt.SignedStringToHeaderValue(ownerTok.Token))
	resp, getErr := s.c.Do(req)
	require.NoError(s.T(), getErr)
	require.Equal(s.T(), http.StatusForbidden, resp.StatusCode)
}

func (s *WithAuthSuite) TestAuthOrgAsRoot() {
	u, urlErr := url.Parse(s.srv.URL + "/org/" + s.org.ID.String())
	require.NoError(s.T(), urlErr)
	req, reqErr := http.NewRequest(http.MethodGet, u.String(), nil)
	require.NoError(s.T(), reqErr)
	req.Header.Add(app.IDHeader, s.st.Root.ID.String())
	req.Header.Add(app.AuthorizationHeader, jwt.SignedStringToHeaderValue(s.tok.Token))
	resp, getErr := s.c.Do(req)
	require.NoError(s.T(), getErr)
	require.Equal(s.T(), http.StatusOK, resp.StatusCode)
}

func (s *WithAuthSuite) TestAuthOrgAsOrgOwner() {
	tokenUrl, tokenUrlErr := url.Parse(s.srv.URL + "/token")
	require.NoError(s.T(), tokenUrlErr)
	tokenRequestValue := jwt.EncodeTokenRequest(s.owner.ID, s.owner.APISecret.String())
	tokenReq := http.Request{
		URL:    tokenUrl,
		Method: http.MethodPost,
		Header: map[string][]string{
			app.IDHeader:           {s.owner.ID.String()},
			app.TokenRequestHeader: {tokenRequestValue},
		},
	}
	resp, postErr := s.c.Do(&tokenReq)
	require.NoError(s.T(), postErr)
	require.Equal(s.T(), http.StatusOK, resp.StatusCode)
	defer resp.Body.Close()
	body, readErr := io.ReadAll(resp.Body)
	require.NoError(s.T(), readErr)
	var ownerTok token.JSONToken
	umErr := json.Unmarshal(body, &ownerTok)
	require.NoError(s.T(), umErr)
	u, urlErr := url.Parse(s.srv.URL + "/org/" + s.org.ID.String())
	require.NoError(s.T(), urlErr)
	req, reqErr := http.NewRequest(http.MethodGet, u.String(), nil)
	require.NoError(s.T(), reqErr)
	req.Header.Add(app.IDHeader, s.owner.ID.String())
	req.Header.Add(app.AuthorizationHeader, jwt.SignedStringToHeaderValue(ownerTok.Token))
	resp, getErr := s.c.Do(req)
	require.NoError(s.T(), getErr)
	require.Equal(s.T(), http.StatusOK, resp.StatusCode)
}

func (s *WithAuthSuite) TestAuthOrgAsOtherOrgOwner() {
	tokenUrl, tokenUrlErr := url.Parse(s.srv.URL + "/token")
	require.NoError(s.T(), tokenUrlErr)
	tokenRequestValue := jwt.EncodeTokenRequest(s.otherOrgOwner.ID, s.otherOrgOwner.APISecret.String())
	tokenReq := http.Request{
		URL:    tokenUrl,
		Method: http.MethodPost,
		Header: map[string][]string{
			app.IDHeader:           {s.otherOrgOwner.ID.String()},
			app.TokenRequestHeader: {tokenRequestValue},
		},
	}
	resp, postErr := s.c.Do(&tokenReq)
	require.NoError(s.T(), postErr)
	require.Equal(s.T(), http.StatusOK, resp.StatusCode)
	defer resp.Body.Close()
	body, readErr := io.ReadAll(resp.Body)
	require.NoError(s.T(), readErr)
	var ownerTok token.JSONToken
	umErr := json.Unmarshal(body, &ownerTok)
	require.NoError(s.T(), umErr)
	u, urlErr := url.Parse(s.srv.URL + "/org/" + s.org.ID.String())
	require.NoError(s.T(), urlErr)
	req, reqErr := http.NewRequest(http.MethodGet, u.String(), nil)
	require.NoError(s.T(), reqErr)
	req.Header.Add(app.IDHeader, s.otherOrgOwner.ID.String())
	req.Header.Add(app.AuthorizationHeader, jwt.SignedStringToHeaderValue(ownerTok.Token))
	resp, getErr := s.c.Do(req)
	require.NoError(s.T(), getErr)
	require.Equal(s.T(), http.StatusForbidden, resp.StatusCode)
}

func (s *WithAuthSuite) TestAuthOrgAsRegularUser() {
	tokenUrl, tokenUrlErr := url.Parse(s.srv.URL + "/token")
	require.NoError(s.T(), tokenUrlErr)
	tokenRequestValue := jwt.EncodeTokenRequest(s.regularUser.ID, s.regularUser.APISecret.String())
	tokenReq := http.Request{
		URL:    tokenUrl,
		Method: http.MethodPost,
		Header: map[string][]string{
			app.IDHeader:           {s.regularUser.ID.String()},
			app.TokenRequestHeader: {tokenRequestValue},
		},
	}
	resp, postErr := s.c.Do(&tokenReq)
	require.NoError(s.T(), postErr)
	require.Equal(s.T(), http.StatusOK, resp.StatusCode)
	defer resp.Body.Close()
	body, readErr := io.ReadAll(resp.Body)
	require.NoError(s.T(), readErr)
	var regularUserTok token.JSONToken
	umErr := json.Unmarshal(body, &regularUserTok)
	require.NoError(s.T(), umErr)
	u, urlErr := url.Parse(s.srv.URL + "/org/" + s.org.ID.String())
	require.NoError(s.T(), urlErr)
	req, reqErr := http.NewRequest(http.MethodGet, u.String(), nil)
	require.NoError(s.T(), reqErr)
	req.Header.Add(app.IDHeader, s.regularUser.ID.String())
	req.Header.Add(app.AuthorizationHeader, jwt.SignedStringToHeaderValue(regularUserTok.Token))
	resp, getErr := s.c.Do(req)
	require.NoError(s.T(), getErr)
	require.Equal(s.T(), http.StatusForbidden, resp.StatusCode)
}

func (s *WithAuthSuite) TestAuthUserAsRoot() {
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

func (s *WithAuthSuite) TestAuthUserAsOrgOwner() {
	tokenUrl, tokenUrlErr := url.Parse(s.srv.URL + "/token")
	require.NoError(s.T(), tokenUrlErr)
	tokenRequestValue := jwt.EncodeTokenRequest(s.owner.ID, s.owner.APISecret.String())
	tokenReq := http.Request{
		URL:    tokenUrl,
		Method: http.MethodPost,
		Header: map[string][]string{
			app.IDHeader:           {s.owner.ID.String()},
			app.TokenRequestHeader: {tokenRequestValue},
		},
	}
	resp, postErr := s.c.Do(&tokenReq)
	require.NoError(s.T(), postErr)
	require.Equal(s.T(), http.StatusOK, resp.StatusCode)
	defer resp.Body.Close()
	body, readErr := io.ReadAll(resp.Body)
	require.NoError(s.T(), readErr)
	var ownerTok token.JSONToken
	umErr := json.Unmarshal(body, &ownerTok)
	require.NoError(s.T(), umErr)
	u, urlErr := url.Parse(s.srv.URL + "/user/" + s.regularUser.ID.String())
	require.NoError(s.T(), urlErr)
	req, reqErr := http.NewRequest(http.MethodGet, u.String(), nil)
	require.NoError(s.T(), reqErr)
	req.Header.Add(app.IDHeader, s.owner.ID.String())
	req.Header.Add(app.AuthorizationHeader, jwt.SignedStringToHeaderValue(ownerTok.Token))
	resp, getErr := s.c.Do(req)
	require.NoError(s.T(), getErr)
	require.Equal(s.T(), http.StatusForbidden, resp.StatusCode)
}

func (s *WithAuthSuite) TestAuthUserAsRegularUser() {
	tokenUrl, tokenUrlErr := url.Parse(s.srv.URL + "/token")
	require.NoError(s.T(), tokenUrlErr)
	tokenRequestValue := jwt.EncodeTokenRequest(s.regularUser.ID, s.regularUser.APISecret.String())
	tokenReq := http.Request{
		URL:    tokenUrl,
		Method: http.MethodPost,
		Header: map[string][]string{
			app.IDHeader:           {s.regularUser.ID.String()},
			app.TokenRequestHeader: {tokenRequestValue},
		},
	}
	resp, postErr := s.c.Do(&tokenReq)
	require.NoError(s.T(), postErr)
	require.Equal(s.T(), http.StatusOK, resp.StatusCode)
	defer resp.Body.Close()
	body, readErr := io.ReadAll(resp.Body)
	require.NoError(s.T(), readErr)
	var regularUserTok token.JSONToken
	umErr := json.Unmarshal(body, &regularUserTok)
	require.NoError(s.T(), umErr)
	u, urlErr := url.Parse(s.srv.URL + "/user/" + s.regularUser.ID.String())
	require.NoError(s.T(), urlErr)
	req, reqErr := http.NewRequest(http.MethodGet, u.String(), nil)
	require.NoError(s.T(), reqErr)
	req.Header.Add(app.IDHeader, s.regularUser.ID.String())
	req.Header.Add(app.AuthorizationHeader, jwt.SignedStringToHeaderValue(regularUserTok.Token))
	resp, getErr := s.c.Do(req)
	require.NoError(s.T(), getErr)
	require.Equal(s.T(), http.StatusOK, resp.StatusCode)
}

func (s *WithAuthSuite) TestAuthUserAsPeerRegularUser() {
	tokenUrl, tokenUrlErr := url.Parse(s.srv.URL + "/token")
	require.NoError(s.T(), tokenUrlErr)
	tokenRequestValue := jwt.EncodeTokenRequest(s.peerRegularUser.ID, s.peerRegularUser.APISecret.String())
	tokenReq := http.Request{
		URL:    tokenUrl,
		Method: http.MethodPost,
		Header: map[string][]string{
			app.IDHeader:           {s.peerRegularUser.ID.String()},
			app.TokenRequestHeader: {tokenRequestValue},
		},
	}
	resp, postErr := s.c.Do(&tokenReq)
	require.NoError(s.T(), postErr)
	require.Equal(s.T(), http.StatusOK, resp.StatusCode)
	defer resp.Body.Close()
	body, readErr := io.ReadAll(resp.Body)
	require.NoError(s.T(), readErr)
	var peerTok token.JSONToken
	umErr := json.Unmarshal(body, &peerTok)
	require.NoError(s.T(), umErr)
	u, urlErr := url.Parse(s.srv.URL + "/user/" + s.regularUser.ID.String())
	require.NoError(s.T(), urlErr)
	req, reqErr := http.NewRequest(http.MethodGet, u.String(), nil)
	require.NoError(s.T(), reqErr)
	req.Header.Add(app.IDHeader, s.peerRegularUser.ID.String())
	req.Header.Add(app.AuthorizationHeader, jwt.SignedStringToHeaderValue(peerTok.Token))
	resp, getErr := s.c.Do(req)
	require.NoError(s.T(), getErr)
	require.Equal(s.T(), http.StatusForbidden, resp.StatusCode)
}

func (s *WithAuthSuite) TestAuthPeerAsRoot() {
	u, urlErr := url.Parse(s.srv.URL + "/peer/" + s.regularUser.ID.String())
	require.NoError(s.T(), urlErr)
	req, reqErr := http.NewRequest(http.MethodGet, u.String(), nil)
	require.NoError(s.T(), reqErr)
	req.Header.Add(app.IDHeader, s.st.Root.ID.String())
	req.Header.Add(app.AuthorizationHeader, jwt.SignedStringToHeaderValue(s.tok.Token))
	resp, getErr := s.c.Do(req)
	require.NoError(s.T(), getErr)
	require.Equal(s.T(), http.StatusOK, resp.StatusCode)
}

func (s *WithAuthSuite) TestAuthPeerAsOrgOwner() {
	tokenUrl, tokenUrlErr := url.Parse(s.srv.URL + "/token")
	require.NoError(s.T(), tokenUrlErr)
	tokenRequestValue := jwt.EncodeTokenRequest(s.owner.ID, s.owner.APISecret.String())
	tokenReq := http.Request{
		URL:    tokenUrl,
		Method: http.MethodPost,
		Header: map[string][]string{
			app.IDHeader:           {s.owner.ID.String()},
			app.TokenRequestHeader: {tokenRequestValue},
		},
	}
	resp, postErr := s.c.Do(&tokenReq)
	require.NoError(s.T(), postErr)
	require.Equal(s.T(), http.StatusOK, resp.StatusCode)
	defer resp.Body.Close()
	body, readErr := io.ReadAll(resp.Body)
	require.NoError(s.T(), readErr)
	var ownerTok token.JSONToken
	umErr := json.Unmarshal(body, &ownerTok)
	require.NoError(s.T(), umErr)
	u, urlErr := url.Parse(s.srv.URL + "/peer/" + s.regularUser.ID.String())
	require.NoError(s.T(), urlErr)
	req, reqErr := http.NewRequest(http.MethodGet, u.String(), nil)
	require.NoError(s.T(), reqErr)
	req.Header.Add(app.IDHeader, s.owner.ID.String())
	req.Header.Add(app.AuthorizationHeader, jwt.SignedStringToHeaderValue(ownerTok.Token))
	resp, getErr := s.c.Do(req)
	require.NoError(s.T(), getErr)
	require.Equal(s.T(), http.StatusForbidden, resp.StatusCode)
}

func (s *WithAuthSuite) TestAuthPeerAsRegularUser() {
	tokenUrl, tokenUrlErr := url.Parse(s.srv.URL + "/token")
	require.NoError(s.T(), tokenUrlErr)
	tokenRequestValue := jwt.EncodeTokenRequest(s.regularUser.ID, s.regularUser.APISecret.String())
	tokenReq := http.Request{
		URL:    tokenUrl,
		Method: http.MethodPost,
		Header: map[string][]string{
			app.IDHeader:           {s.regularUser.ID.String()},
			app.TokenRequestHeader: {tokenRequestValue},
		},
	}
	resp, postErr := s.c.Do(&tokenReq)
	require.NoError(s.T(), postErr)
	require.Equal(s.T(), http.StatusOK, resp.StatusCode)
	defer resp.Body.Close()
	body, readErr := io.ReadAll(resp.Body)
	require.NoError(s.T(), readErr)
	var regularUserTok token.JSONToken
	umErr := json.Unmarshal(body, &regularUserTok)
	require.NoError(s.T(), umErr)
	u, urlErr := url.Parse(s.srv.URL + "/peer/" + s.regularUser.ID.String())
	require.NoError(s.T(), urlErr)
	req, reqErr := http.NewRequest(http.MethodGet, u.String(), nil)
	require.NoError(s.T(), reqErr)
	req.Header.Add(app.IDHeader, s.regularUser.ID.String())
	req.Header.Add(app.AuthorizationHeader, jwt.SignedStringToHeaderValue(regularUserTok.Token))
	resp, getErr := s.c.Do(req)
	require.NoError(s.T(), getErr)
	require.Equal(s.T(), http.StatusOK, resp.StatusCode)
}

func (s *WithAuthSuite) TestAuthPeerAsPeerRegularUser() {
	tokenUrl, tokenUrlErr := url.Parse(s.srv.URL + "/token")
	require.NoError(s.T(), tokenUrlErr)
	tokenRequestValue := jwt.EncodeTokenRequest(s.peerRegularUser.ID, s.peerRegularUser.APISecret.String())
	tokenReq := http.Request{
		URL:    tokenUrl,
		Method: http.MethodPost,
		Header: map[string][]string{
			app.IDHeader:           {s.peerRegularUser.ID.String()},
			app.TokenRequestHeader: {tokenRequestValue},
		},
	}
	resp, postErr := s.c.Do(&tokenReq)
	require.NoError(s.T(), postErr)
	require.Equal(s.T(), http.StatusOK, resp.StatusCode)
	defer resp.Body.Close()
	body, readErr := io.ReadAll(resp.Body)
	require.NoError(s.T(), readErr)
	var peerTok token.JSONToken
	umErr := json.Unmarshal(body, &peerTok)
	require.NoError(s.T(), umErr)
	u, urlErr := url.Parse(s.srv.URL + "/peer/" + s.regularUser.ID.String())
	require.NoError(s.T(), urlErr)
	req, reqErr := http.NewRequest(http.MethodGet, u.String(), nil)
	require.NoError(s.T(), reqErr)
	req.Header.Add(app.IDHeader, s.peerRegularUser.ID.String())
	req.Header.Add(app.AuthorizationHeader, jwt.SignedStringToHeaderValue(peerTok.Token))
	resp, getErr := s.c.Do(req)
	require.NoError(s.T(), getErr)
	require.Equal(s.T(), http.StatusOK, resp.StatusCode)
}

func (s *WithAuthSuite) TestAuthPeerAsOtherOrgRegularUser() {
	tokenUrl, tokenUrlErr := url.Parse(s.srv.URL + "/token")
	require.NoError(s.T(), tokenUrlErr)
	tokenRequestValue := jwt.EncodeTokenRequest(s.otherOrgRegularUser.ID, s.otherOrgRegularUser.APISecret.String())
	tokenReq := http.Request{
		URL:    tokenUrl,
		Method: http.MethodPost,
		Header: map[string][]string{
			app.IDHeader:           {s.otherOrgRegularUser.ID.String()},
			app.TokenRequestHeader: {tokenRequestValue},
		},
	}
	resp, postErr := s.c.Do(&tokenReq)
	require.NoError(s.T(), postErr)
	require.Equal(s.T(), http.StatusOK, resp.StatusCode)
	defer resp.Body.Close()
	body, readErr := io.ReadAll(resp.Body)
	require.NoError(s.T(), readErr)
	var regularUserTok token.JSONToken
	umErr := json.Unmarshal(body, &regularUserTok)
	require.NoError(s.T(), umErr)
	u, urlErr := url.Parse(s.srv.URL + "/peer/" + s.regularUser.ID.String())
	require.NoError(s.T(), urlErr)
	req, reqErr := http.NewRequest(http.MethodGet, u.String(), nil)
	require.NoError(s.T(), reqErr)
	req.Header.Add(app.IDHeader, s.otherOrgRegularUser.ID.String())
	req.Header.Add(app.AuthorizationHeader, jwt.SignedStringToHeaderValue(regularUserTok.Token))
	resp, getErr := s.c.Do(req)
	require.NoError(s.T(), getErr)
	require.Equal(s.T(), http.StatusForbidden, resp.StatusCode)
}

func (s *WithAuthSuite) TearDownSuite() {
	s.srv.Close()
}

func TestWithAuthSuite(t *testing.T) {
	suite.Run(t, new(WithAuthSuite))
}
