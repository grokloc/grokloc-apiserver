package testing

import (
	"context"
	"net/http"
	"net/url"

	"github.com/grokloc/grokloc-apiserver/pkg/app"
	"github.com/grokloc/grokloc-apiserver/pkg/app/admin/org"
	"github.com/grokloc/grokloc-apiserver/pkg/app/jwt"
	"github.com/grokloc/grokloc-apiserver/pkg/app/models"
	app_testing "github.com/grokloc/grokloc-apiserver/pkg/app/testing"
	"github.com/stretchr/testify/require"
)

func (s *OrgSuite) TestDeleteAsRoot() {
	conn, connErr := s.st.Master.Acquire(context.Background())
	require.NoError(s.T(), connErr)
	defer conn.Release()
	// create an org to DELETE to
	o, _, _, oErr := app_testing.TestOrgAndUser(conn.Conn(), s.st)
	require.NoError(s.T(), oErr)

	u, urlErr := url.Parse(s.srv.URL + app.APIPath + s.st.APIVersion + "/org/" + o.ID.String())
	require.NoError(s.T(), urlErr)
	req, reqErr := http.NewRequest(http.MethodDelete, u.String(), nil)
	require.NoError(s.T(), reqErr)
	req.Header.Add(app.IDHeader, s.st.Root.ID.String())
	req.Header.Add(app.AuthorizationHeader, jwt.SignedStringToHeaderValue(s.tok.Token))
	resp, deleteErr := s.c.Do(req)
	require.NoError(s.T(), deleteErr)
	require.Equal(s.T(), http.StatusNoContent, resp.StatusCode)

	// read out to confirm
	oRead, oErr := org.Read(context.Background(), conn.Conn(), o.ID)
	require.NoError(s.T(), oErr)
	require.Equal(s.T(), o.ID, oRead.ID)
	require.Equal(s.T(), models.StatusInactive, oRead.Meta.Status)
}

// TestDeleteAsOrgOwner demonstrates that org owner auth cannot update an org.
func (s *OrgSuite) TestDeleteAsOrgOwner() {
	u, urlErr := url.Parse(s.srv.URL + app.APIPath + s.st.APIVersion + "/org/" + s.o.ID.String())
	require.NoError(s.T(), urlErr)
	req, reqErr := http.NewRequest(http.MethodDelete, u.String(), nil)
	require.NoError(s.T(), reqErr)
	req.Header.Add(app.IDHeader, s.owner.ID.String())
	req.Header.Add(app.AuthorizationHeader, jwt.SignedStringToHeaderValue(s.ownerTok.Token))
	resp, deleteErr := s.c.Do(req)
	require.NoError(s.T(), deleteErr)
	require.Equal(s.T(), http.StatusForbidden, resp.StatusCode)
}

// TestDeleteAsRegularUser demonstrates that user auth cannot update an org.
func (s *OrgSuite) TestDeleteAsRegularUser() {
	u, urlErr := url.Parse(s.srv.URL + app.APIPath + s.st.APIVersion + "/org/" + s.o.ID.String())
	require.NoError(s.T(), urlErr)
	req, reqErr := http.NewRequest(http.MethodDelete, u.String(), nil)
	require.NoError(s.T(), reqErr)
	req.Header.Add(app.IDHeader, s.regularUser.ID.String())
	req.Header.Add(app.AuthorizationHeader, jwt.SignedStringToHeaderValue(s.regularUserTok.Token))
	resp, deleteErr := s.c.Do(req)
	require.NoError(s.T(), deleteErr)
	require.Equal(s.T(), http.StatusForbidden, resp.StatusCode)
}

func (s *OrgSuite) TestDeleteFound() {
	u, urlErr := url.Parse(s.srv.URL + app.APIPath + s.st.APIVersion + "/org/" + models.NewID().String())
	require.NoError(s.T(), urlErr)
	req, reqErr := http.NewRequest(http.MethodDelete, u.String(), nil)
	require.NoError(s.T(), reqErr)
	req.Header.Add(app.IDHeader, s.st.Root.ID.String())
	req.Header.Add(app.AuthorizationHeader, jwt.SignedStringToHeaderValue(s.tok.Token))
	resp, deleteErr := s.c.Do(req)
	require.NoError(s.T(), deleteErr)
	require.Equal(s.T(), http.StatusNotFound, resp.StatusCode)
}
