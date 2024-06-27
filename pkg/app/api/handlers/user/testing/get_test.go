package testing

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"

	"github.com/grokloc/grokloc-apiserver/pkg/app"
	"github.com/grokloc/grokloc-apiserver/pkg/app/admin/user"
	"github.com/grokloc/grokloc-apiserver/pkg/app/jwt"
	"github.com/grokloc/grokloc-apiserver/pkg/app/models"
	app_testing "github.com/grokloc/grokloc-apiserver/pkg/app/testing"
	"github.com/grokloc/grokloc-apiserver/pkg/safe"
	"github.com/grokloc/grokloc-apiserver/pkg/security"
	"github.com/stretchr/testify/require"
)

func (s *UserSuite) TestGetAsRoot() {
	conn, connErr := s.st.Master.Acquire(context.Background())
	require.NoError(s.T(), connErr)
	defer conn.Release()
	_, _, regularUser, oErr := app_testing.TestOrgAndUser(conn.Conn(), s.st)
	require.NoError(s.T(), oErr)
	u, urlErr := url.Parse(s.srv.URL + app.APIPath + s.st.APIVersion + "/user/" + regularUser.ID.String())
	require.NoError(s.T(), urlErr)

	req, reqErr := http.NewRequest(http.MethodGet, u.String(), nil)
	require.NoError(s.T(), reqErr)
	req.Header.Add(app.IDHeader, s.st.Root.ID.String())
	req.Header.Add(app.AuthorizationHeader, jwt.SignedStringToHeaderValue(s.tok.Token))
	resp, getErr := s.c.Do(req)
	require.NoError(s.T(), getErr)
	require.Equal(s.T(), http.StatusOK, resp.StatusCode)

	// get response body (json serialized user)
	decoder := json.NewDecoder(resp.Body)
	decoder.DisallowUnknownFields()
	var usr user.User
	dcErr := decoder.Decode(&usr)
	require.NoError(s.T(), dcErr)

	require.Equal(s.T(), regularUser.ID, usr.ID)
	require.Equal(s.T(), regularUser.Org, usr.Org)
	require.NotEqual(s.T(), regularUser.Password, usr.Password)
	require.Equal(s.T(), regularUser.APISecret, usr.APISecret)
	require.Equal(s.T(), regularUser.APISecretDigest, usr.APISecretDigest)
	require.Equal(s.T(), regularUser.DisplayName, usr.DisplayName)
	require.Equal(s.T(), regularUser.DisplayNameDigest, usr.DisplayNameDigest)
	require.Equal(s.T(), regularUser.Email, usr.Email)
	require.Equal(s.T(), regularUser.EmailDigest, usr.EmailDigest)
	require.Equal(s.T(), regularUser.Meta, usr.Meta)
}

func (s *UserSuite) TestGetAsOrgOwner() {
	u, urlErr := url.Parse(s.srv.URL + app.APIPath + s.st.APIVersion + "/user/" + s.regularUser.ID.String())
	require.NoError(s.T(), urlErr)
	req, reqErr := http.NewRequest(http.MethodGet, u.String(), nil)
	require.NoError(s.T(), reqErr)
	req.Header.Add(app.IDHeader, s.owner.ID.String())
	req.Header.Add(app.AuthorizationHeader, jwt.SignedStringToHeaderValue(s.ownerTok.Token))
	resp, getErr := s.c.Do(req)
	require.NoError(s.T(), getErr)
	require.Equal(s.T(), http.StatusOK, resp.StatusCode)

	// get response body (json serialized user)
	decoder := json.NewDecoder(resp.Body)
	decoder.DisallowUnknownFields()
	var usr user.User
	dcErr := decoder.Decode(&usr)
	require.NoError(s.T(), dcErr)

	require.Equal(s.T(), s.regularUser.ID, usr.ID)
	require.Equal(s.T(), s.regularUser.Org, usr.Org)
	require.NotEqual(s.T(), s.regularUser.Password, usr.Password)
	require.Equal(s.T(), s.regularUser.APISecret, usr.APISecret)
	require.Equal(s.T(), s.regularUser.APISecretDigest, usr.APISecretDigest)
	require.Equal(s.T(), s.regularUser.DisplayName, usr.DisplayName)
	require.Equal(s.T(), s.regularUser.DisplayNameDigest, usr.DisplayNameDigest)
	require.Equal(s.T(), s.regularUser.Email, usr.Email)
	require.Equal(s.T(), s.regularUser.EmailDigest, usr.EmailDigest)
	require.Equal(s.T(), s.regularUser.Meta, usr.Meta)

	// try to get a user (root) that org owner has no permission to access
	u, urlErr = url.Parse(s.srv.URL + app.APIPath + s.st.APIVersion + "/user/" + s.st.Root.ID.String())
	require.NoError(s.T(), urlErr)
	req, reqErr = http.NewRequest(http.MethodGet, u.String(), nil)
	require.NoError(s.T(), reqErr)
	req.Header.Add(app.IDHeader, s.owner.ID.String())
	req.Header.Add(app.AuthorizationHeader, jwt.SignedStringToHeaderValue(s.ownerTok.Token))
	resp, getErr = s.c.Do(req)
	require.NoError(s.T(), getErr)
	require.Equal(s.T(), http.StatusForbidden, resp.StatusCode)
}

func (s *UserSuite) TestGetAsRegularUser() {
	u, urlErr := url.Parse(s.srv.URL + app.APIPath + s.st.APIVersion + "/user/" + s.regularUser.ID.String())
	require.NoError(s.T(), urlErr)
	req, reqErr := http.NewRequest(http.MethodGet, u.String(), nil)
	require.NoError(s.T(), reqErr)
	req.Header.Add(app.IDHeader, s.regularUser.ID.String())
	req.Header.Add(app.AuthorizationHeader, jwt.SignedStringToHeaderValue(s.regularUserTok.Token))
	resp, getErr := s.c.Do(req)
	require.NoError(s.T(), getErr)
	require.Equal(s.T(), http.StatusOK, resp.StatusCode)

	// get response body (json serialized user)
	decoder := json.NewDecoder(resp.Body)
	decoder.DisallowUnknownFields()
	var usr user.User
	dcErr := decoder.Decode(&usr)
	require.NoError(s.T(), dcErr)

	require.Equal(s.T(), s.regularUser.ID, usr.ID)
	require.Equal(s.T(), s.regularUser.Org, usr.Org)
	require.NotEqual(s.T(), s.regularUser.Password, usr.Password)
	require.Equal(s.T(), s.regularUser.APISecret, usr.APISecret)
	require.Equal(s.T(), s.regularUser.APISecretDigest, usr.APISecretDigest)
	require.Equal(s.T(), s.regularUser.DisplayName, usr.DisplayName)
	require.Equal(s.T(), s.regularUser.DisplayNameDigest, usr.DisplayNameDigest)
	require.Equal(s.T(), s.regularUser.Email, usr.Email)
	require.Equal(s.T(), s.regularUser.EmailDigest, usr.EmailDigest)
	require.Equal(s.T(), s.regularUser.Meta, usr.Meta)

	// try to get a user (root) that regular user has no permission to access
	u, urlErr = url.Parse(s.srv.URL + app.APIPath + s.st.APIVersion + "/user/" + s.st.Root.ID.String())
	require.NoError(s.T(), urlErr)
	req, reqErr = http.NewRequest(http.MethodGet, u.String(), nil)
	req.Header.Add(app.IDHeader, s.regularUser.ID.String())
	req.Header.Add(app.AuthorizationHeader, jwt.SignedStringToHeaderValue(s.regularUserTok.Token))
	require.NoError(s.T(), reqErr)
	resp, getErr = s.c.Do(req)
	require.NoError(s.T(), getErr)
	require.Equal(s.T(), http.StatusForbidden, resp.StatusCode)

	// create another user in the same org, try to read it
	conn, connErr := s.st.Master.Acquire(context.Background())
	require.NoError(s.T(), connErr)
	defer conn.Release()
	displayName := safe.TrustedVarChar(security.RandString())
	email := safe.TrustedVarChar(security.RandString())
	password, passwordErr := security.DerivePassword(security.RandString(), s.st.Argon2Config)
	require.NoError(s.T(), passwordErr)
	peerUser, createErr := user.Create(context.Background(), conn.Conn(), displayName, email, s.o.ID, *password, s.st.VersionKey)
	require.NoError(s.T(), createErr)
	u, urlErr = url.Parse(s.srv.URL + app.APIPath + s.st.APIVersion + "/user/" + peerUser.ID.String())
	require.NoError(s.T(), urlErr)
	req, reqErr = http.NewRequest(http.MethodGet, u.String(), nil)
	req.Header.Add(app.IDHeader, s.regularUser.ID.String())
	req.Header.Add(app.AuthorizationHeader, jwt.SignedStringToHeaderValue(s.regularUserTok.Token))
	require.NoError(s.T(), reqErr)
	resp, getErr = s.c.Do(req)
	require.NoError(s.T(), getErr)
	require.Equal(s.T(), http.StatusForbidden, resp.StatusCode)
}

func (s *UserSuite) TestGetNotFound() {
	u, urlErr := url.Parse(s.srv.URL + app.APIPath + s.st.APIVersion + "/user/" + models.NewID().String())
	require.NoError(s.T(), urlErr)
	req, reqErr := http.NewRequest(http.MethodGet, u.String(), nil)
	require.NoError(s.T(), reqErr)
	req.Header.Add(app.IDHeader, s.st.Root.ID.String())
	req.Header.Add(app.AuthorizationHeader, jwt.SignedStringToHeaderValue(s.tok.Token))
	resp, getErr := s.c.Do(req)
	require.NoError(s.T(), getErr)
	require.Equal(s.T(), http.StatusNotFound, resp.StatusCode)
}
