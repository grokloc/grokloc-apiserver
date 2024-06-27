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

func (s *UserSuite) TestDeleteAsRoot() {
	conn, connErr := s.st.Master.Acquire(context.Background())
	require.NoError(s.T(), connErr)
	defer conn.Release()
	// create a user to DELETE to
	_, _, regularUser, oErr := app_testing.TestOrgAndUser(conn.Conn(), s.st)
	require.NoError(s.T(), oErr)

	u, urlErr := url.Parse(s.srv.URL + app.APIPath + s.st.APIVersion + "/user/" + regularUser.ID.String())
	require.NoError(s.T(), urlErr)
	req, reqErr := http.NewRequest(http.MethodDelete, u.String(), nil)
	require.NoError(s.T(), reqErr)
	req.Header.Add(app.IDHeader, s.st.Root.ID.String())
	req.Header.Add(app.AuthorizationHeader, jwt.SignedStringToHeaderValue(s.tok.Token))
	resp, deleteErr := s.c.Do(req)
	require.NoError(s.T(), deleteErr)
	require.Equal(s.T(), http.StatusNoContent, resp.StatusCode)

	// read out to confirm
	uRead, uErr := user.Read(context.Background(), conn.Conn(), s.st.VersionKey, regularUser.ID)
	require.NoError(s.T(), uErr)
	require.Equal(s.T(), regularUser.ID, uRead.ID)
	require.Equal(s.T(), models.StatusInactive, uRead.Meta.Status)
}

func (s *UserSuite) TestDeleteAsOrgOwner() {
	// make a new org owner with a regular user to delete
	conn, connErr := s.st.Master.Acquire(context.Background())
	require.NoError(s.T(), connErr)
	defer conn.Release()
	_, owner, regularUser, oErr := app_testing.TestOrgAndUser(conn.Conn(), s.st)
	require.NoError(s.T(), oErr)
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
	require.Equal(s.T(), resp.StatusCode, http.StatusOK)
	defer resp.Body.Close()
	body, readErr := io.ReadAll(resp.Body)
	require.NoError(s.T(), readErr)
	var ownerTok token.JSONToken
	umErr := json.Unmarshal(body, &ownerTok)
	require.NoError(s.T(), umErr)
	require.NotEmpty(s.T(), ownerTok.Token)

	// try to set to inactive
	u, urlErr := url.Parse(s.srv.URL + app.APIPath + s.st.APIVersion + "/user/" + regularUser.ID.String())
	require.NoError(s.T(), urlErr)
	req, reqErr := http.NewRequest(http.MethodDelete, u.String(), nil)
	require.NoError(s.T(), reqErr)
	req.Header.Add(app.IDHeader, owner.ID.String())
	req.Header.Add(app.AuthorizationHeader, jwt.SignedStringToHeaderValue(ownerTok.Token))
	resp, deleteErr := s.c.Do(req)
	require.NoError(s.T(), deleteErr)
	require.Equal(s.T(), http.StatusNoContent, resp.StatusCode)

	// read out to confirm
	uRead, uErr := user.Read(context.Background(), conn.Conn(), s.st.VersionKey, regularUser.ID)
	require.NoError(s.T(), uErr)
	require.Equal(s.T(), regularUser.ID, uRead.ID)
	require.Equal(s.T(), models.StatusInactive, uRead.Meta.Status)
}

// TestDeleteAsRegularUser demonstrates that user auth cannot delete a user.
func (s *UserSuite) TestDeleteAsRegularUser() {
	u, urlErr := url.Parse(s.srv.URL + app.APIPath + s.st.APIVersion + "/user/" + s.regularUser.ID.String())
	require.NoError(s.T(), urlErr)
	req, reqErr := http.NewRequest(http.MethodDelete, u.String(), nil)
	require.NoError(s.T(), reqErr)
	req.Header.Add(app.IDHeader, s.regularUser.ID.String())
	req.Header.Add(app.AuthorizationHeader, jwt.SignedStringToHeaderValue(s.regularUserTok.Token))
	resp, deleteErr := s.c.Do(req)
	require.NoError(s.T(), deleteErr)
	require.Equal(s.T(), http.StatusForbidden, resp.StatusCode)
}

func (s *UserSuite) TestDeleteNotFound() {
	u, urlErr := url.Parse(s.srv.URL + app.APIPath + s.st.APIVersion + "/user/" + models.NewID().String())
	require.NoError(s.T(), urlErr)
	req, reqErr := http.NewRequest(http.MethodDelete, u.String(), nil)
	require.NoError(s.T(), reqErr)
	req.Header.Add(app.IDHeader, s.st.Root.ID.String())
	req.Header.Add(app.AuthorizationHeader, jwt.SignedStringToHeaderValue(s.tok.Token))
	resp, deleteErr := s.c.Do(req)
	require.NoError(s.T(), deleteErr)
	require.Equal(s.T(), http.StatusNotFound, resp.StatusCode)
}
