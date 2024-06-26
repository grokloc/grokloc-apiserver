package testing

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"

	"github.com/grokloc/grokloc-apiserver/pkg/app"
	"github.com/grokloc/grokloc-apiserver/pkg/app/admin/org"
	"github.com/grokloc/grokloc-apiserver/pkg/app/jwt"
	"github.com/grokloc/grokloc-apiserver/pkg/app/models"
	app_testing "github.com/grokloc/grokloc-apiserver/pkg/app/testing"
	"github.com/stretchr/testify/require"
)

func (s *OrgSuite) TestGetAsRoot() {
	conn, connErr := s.st.Master.Acquire(context.Background())
	require.NoError(s.T(), connErr)
	defer conn.Release()
	// create an org to GET
	o, _, _, oErr := app_testing.TestOrgAndUser(conn.Conn(), s.st)
	require.NoError(s.T(), oErr)

	u, urlErr := url.Parse(s.srv.URL + app.APIPath + s.st.APIVersion + "/org/" + o.ID.String())
	require.NoError(s.T(), urlErr)
	req, reqErr := http.NewRequest(http.MethodGet, u.String(), nil)
	require.NoError(s.T(), reqErr)
	req.Header.Add(app.IDHeader, s.st.Root.ID.String())
	req.Header.Add(app.AuthorizationHeader, jwt.SignedStringToHeaderValue(s.tok.Token))
	resp, getErr := s.c.Do(req)
	require.NoError(s.T(), getErr)
	require.Equal(s.T(), http.StatusOK, resp.StatusCode)
	// get response body (json serialized org)
	decoder := json.NewDecoder(resp.Body)
	decoder.DisallowUnknownFields()
	var oRead org.Org
	dcErr := decoder.Decode(&oRead)
	require.Equal(s.T(), o.ID.String(), oRead.ID.String())
	require.NoError(s.T(), dcErr)
}

func (s *OrgSuite) TestGetAsOrgOwner() {
	u, urlErr := url.Parse(s.srv.URL + app.APIPath + s.st.APIVersion + "/org/" + s.o.ID.String())
	require.NoError(s.T(), urlErr)
	req, reqErr := http.NewRequest(http.MethodGet, u.String(), nil)
	require.NoError(s.T(), reqErr)
	req.Header.Add(app.IDHeader, s.owner.ID.String())
	req.Header.Add(app.AuthorizationHeader, jwt.SignedStringToHeaderValue(s.ownerTok.Token))
	resp, getErr := s.c.Do(req)
	require.NoError(s.T(), getErr)
	require.Equal(s.T(), http.StatusOK, resp.StatusCode)
	// get response body (json serialized org)
	decoder := json.NewDecoder(resp.Body)
	decoder.DisallowUnknownFields()
	oRead := org.Org{}
	dcErr := decoder.Decode(&oRead)
	require.Equal(s.T(), s.o.ID.String(), oRead.ID.String())
	require.NoError(s.T(), dcErr)

	// ty to get an org not owned by owner
	u, urlErr = url.Parse(s.srv.URL + app.APIPath + s.st.APIVersion + "/org/" + s.st.Root.Org.String())
	require.NoError(s.T(), urlErr)
	req, reqErr = http.NewRequest(http.MethodGet, u.String(), nil)
	require.NoError(s.T(), reqErr)
	req.Header.Add(app.IDHeader, s.owner.ID.String())
	req.Header.Add(app.AuthorizationHeader, jwt.SignedStringToHeaderValue(s.ownerTok.Token))
	resp, getErr = s.c.Do(req)
	require.NoError(s.T(), getErr)
	require.Equal(s.T(), http.StatusForbidden, resp.StatusCode)
}

func (s *OrgSuite) TestGetAsRegularUser() {
	u, urlErr := url.Parse(s.srv.URL + app.APIPath + s.st.APIVersion + "/org/" + s.o.ID.String())
	require.NoError(s.T(), urlErr)
	req, reqErr := http.NewRequest(http.MethodGet, u.String(), nil)
	require.NoError(s.T(), reqErr)
	req.Header.Add(app.IDHeader, s.regularUser.ID.String())
	req.Header.Add(app.AuthorizationHeader, jwt.SignedStringToHeaderValue(s.regularUserTok.Token))
	resp, getErr := s.c.Do(req)
	require.NoError(s.T(), getErr)
	require.Equal(s.T(), http.StatusForbidden, resp.StatusCode)
}

func (s *OrgSuite) TestGetNotFound() {
	u, urlErr := url.Parse(s.srv.URL + app.APIPath + s.st.APIVersion + "/org/" + models.NewID().String())
	require.NoError(s.T(), urlErr)
	req, reqErr := http.NewRequest(http.MethodGet, u.String(), nil)
	require.NoError(s.T(), reqErr)
	req.Header.Add(app.IDHeader, s.st.Root.ID.String())
	req.Header.Add(app.AuthorizationHeader, jwt.SignedStringToHeaderValue(s.tok.Token))
	resp, getErr := s.c.Do(req)
	require.NoError(s.T(), getErr)
	require.Equal(s.T(), http.StatusNotFound, resp.StatusCode)
}
