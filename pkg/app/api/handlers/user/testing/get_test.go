package testing

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"

	"github.com/grokloc/grokloc-apiserver/pkg/app"
	"github.com/grokloc/grokloc-apiserver/pkg/app/admin/user"
	"github.com/grokloc/grokloc-apiserver/pkg/app/api/handlers/token"
	"github.com/grokloc/grokloc-apiserver/pkg/app/jwt"
	"github.com/grokloc/grokloc-apiserver/pkg/app/models"
	app_testing "github.com/grokloc/grokloc-apiserver/pkg/app/testing"
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
	conn, connErr := s.st.Master.Acquire(context.Background())
	require.NoError(s.T(), connErr)
	defer conn.Release()
	_, owner, regularUser, oErr := app_testing.TestOrgAndUser(conn.Conn(), s.st)
	require.NoError(s.T(), oErr)

	// make token request for org owner
	tokenReqUrl, tokenReqUrlErr := url.Parse(s.srv.URL + "/token")
	require.NoError(s.T(), tokenReqUrlErr)
	ownerTokenRequest := jwt.EncodeTokenRequest(owner.ID, owner.APISecret.String())
	ownerReq := http.Request{
		URL:    tokenReqUrl,
		Method: http.MethodPost,
		Header: map[string][]string{
			app.IDHeader:           {owner.ID.String()},
			app.TokenRequestHeader: {ownerTokenRequest},
		},
	}
	resp, postErr := s.c.Do(&ownerReq)
	require.NoError(s.T(), postErr)
	require.Equal(s.T(), http.StatusOK, resp.StatusCode)
	defer resp.Body.Close()
	body, readErr := io.ReadAll(resp.Body)
	require.NoError(s.T(), readErr)
	var ownerTok token.JSONToken
	umErr := json.Unmarshal(body, &ownerTok)
	require.NoError(s.T(), umErr)
	require.NotEmpty(s.T(), ownerTok.Token)

	u, urlErr := url.Parse(s.srv.URL + app.APIPath + s.st.APIVersion + "/user/" + regularUser.ID.String())
	require.NoError(s.T(), urlErr)
	req, reqErr := http.NewRequest(http.MethodGet, u.String(), nil)
	require.NoError(s.T(), reqErr)
	req.Header.Add(app.IDHeader, owner.ID.String())
	req.Header.Add(app.AuthorizationHeader, jwt.SignedStringToHeaderValue(ownerTok.Token))
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

	// try to get a user (root) that org owner has no permission to access
	u, urlErr = url.Parse(s.srv.URL + app.APIPath + s.st.APIVersion + "/user/" + s.st.Root.ID.String())
	require.NoError(s.T(), urlErr)
	req, reqErr = http.NewRequest(http.MethodGet, u.String(), nil)
	require.NoError(s.T(), reqErr)
	req.Header.Add(app.IDHeader, owner.ID.String())
	req.Header.Add(app.AuthorizationHeader, jwt.SignedStringToHeaderValue(ownerTok.Token))
	resp, getErr = s.c.Do(req)
	require.NoError(s.T(), getErr)
	require.Equal(s.T(), http.StatusForbidden, resp.StatusCode)
}

func (s *UserSuite) TestGetAsRegularUser() {
	conn, connErr := s.st.Master.Acquire(context.Background())
	require.NoError(s.T(), connErr)
	defer conn.Release()
	_, _, regularUser, oErr := app_testing.TestOrgAndUser(conn.Conn(), s.st)
	require.NoError(s.T(), oErr)

	// make token request for org owner
	tokenReqUrl, tokenReqUrlErr := url.Parse(s.srv.URL + "/token")
	require.NoError(s.T(), tokenReqUrlErr)
	regularUserTokenRequest := jwt.EncodeTokenRequest(regularUser.ID, regularUser.APISecret.String())
	regularUserReq := http.Request{
		URL:    tokenReqUrl,
		Method: http.MethodPost,
		Header: map[string][]string{
			app.IDHeader:           {regularUser.ID.String()},
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

	u, urlErr := url.Parse(s.srv.URL + app.APIPath + s.st.APIVersion + "/user/" + regularUser.ID.String())
	require.NoError(s.T(), urlErr)
	req, reqErr := http.NewRequest(http.MethodGet, u.String(), nil)
	require.NoError(s.T(), reqErr)
	req.Header.Add(app.IDHeader, regularUser.ID.String())
	req.Header.Add(app.AuthorizationHeader, jwt.SignedStringToHeaderValue(regularUserTok.Token))
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

	// try to get a user (root) that regular user has no permission to access
	u, urlErr = url.Parse(s.srv.URL + app.APIPath + s.st.APIVersion + "/user/" + s.st.Root.ID.String())
	require.NoError(s.T(), urlErr)
	req, reqErr = http.NewRequest(http.MethodGet, u.String(), nil)
	req.Header.Add(app.IDHeader, regularUser.ID.String())
	req.Header.Add(app.AuthorizationHeader, jwt.SignedStringToHeaderValue(regularUserTok.Token))
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
