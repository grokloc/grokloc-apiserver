package testing

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/grokloc/grokloc-apiserver/pkg/app"
	"github.com/grokloc/grokloc-apiserver/pkg/safe"
	"github.com/grokloc/grokloc-apiserver/pkg/security"

	"github.com/grokloc/grokloc-apiserver/pkg/app/admin/org"
	"github.com/grokloc/grokloc-apiserver/pkg/app/admin/user"
	"github.com/grokloc/grokloc-apiserver/pkg/app/api/handlers/token"
	"github.com/grokloc/grokloc-apiserver/pkg/app/jwt"
	app_testing "github.com/grokloc/grokloc-apiserver/pkg/app/testing"
	"github.com/stretchr/testify/require"
)

func (s *OrgSuite) TestPostAsRoot() {
	ev := org.CreateEvent{
		Name:             safe.TrustedVarChar(security.RandString()),
		OwnerDisplayName: safe.TrustedVarChar(security.RandString()),
		OwnerEmail:       safe.TrustedVarChar(security.RandString()),
		OwnerPassword:    safe.TrustedPassword(security.RandString()),
		Role:             s.st.DefaultRole,
	}
	bs, bsErr := json.Marshal(ev)
	require.NoError(s.T(), bsErr)
	u, urlErr := url.Parse(s.srv.URL + "/api/" + s.st.APIVersion + "/org")
	require.NoError(s.T(), urlErr)
	req, reqErr := http.NewRequest(http.MethodPost, u.String(), bytes.NewBuffer(bs))
	require.NoError(s.T(), reqErr)
	req.Header.Add(app.IDHeader, s.st.Root.ID.String())
	req.Header.Add(app.AuthorizationHeader, jwt.SignedStringToHeaderValue(s.tok.Token))
	resp, postErr := s.c.Do(req)
	require.NoError(s.T(), postErr)
	require.Equal(s.T(), http.StatusCreated, resp.StatusCode)
	// get response body (json serialized org)
	decoder := json.NewDecoder(resp.Body)
	decoder.DisallowUnknownFields()
	var o org.Org
	dcErr := decoder.Decode(&o)
	require.NoError(s.T(), dcErr)
	require.Equal(s.T(), ev.Name, o.Name)
	// parse the id from the location, then do a read on it
	// to verify
	location, locationErr := resp.Location()
	require.NoError(s.T(), locationErr)
	pathElts := strings.Split(location.Path, "/")
	require.True(s.T(), len(pathElts) != 0)
	id := pathElts[len(pathElts)-1]
	require.Equal(s.T(), o.ID.String(), id)
	conn, connErr := s.st.Master.Acquire(context.Background())
	require.NoError(s.T(), connErr)
	defer conn.Release()
	oRead, oReadErr := org.Read(context.Background(), conn.Conn(), o.ID)
	require.NoError(s.T(), oReadErr)
	require.Equal(s.T(), o.ID.String(), oRead.ID.String())
	uRead, uReadErr := user.Read(context.Background(), conn.Conn(), s.st.VersionKey, oRead.Owner)
	require.NoError(s.T(), uReadErr)
	require.Equal(s.T(), ev.OwnerDisplayName, uRead.DisplayName)
	require.Equal(s.T(), ev.OwnerEmail, uRead.Email)
	require.NotEqual(s.T(), ev.OwnerPassword, uRead.Password)
	match, matchErr := security.VerifyPassword(ev.OwnerPassword.String(), uRead.Password)
	require.NoError(s.T(), matchErr)
	require.True(s.T(), match)
}

// TestPostAsOrgOwner demonstrates that org owner auth cannot create an org.
func (s *OrgSuite) TestPostAsOrgOwner() {
	conn, connErr := s.st.Master.Acquire(context.Background())
	require.NoError(s.T(), connErr)
	defer conn.Release()
	_, owner, _, oErr := app_testing.TestOrgAndUser(conn.Conn(), s.st)
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
	require.Equal(s.T(), resp.StatusCode, http.StatusOK)
	defer resp.Body.Close()
	body, readErr := io.ReadAll(resp.Body)
	require.NoError(s.T(), readErr)
	var ownerTok token.JSONToken
	umErr := json.Unmarshal(body, &ownerTok)
	require.NoError(s.T(), umErr)
	require.NotEmpty(s.T(), ownerTok.Token)
	// have owner attempt to create an org
	ev := org.CreateEvent{
		Name:             safe.TrustedVarChar(security.RandString()),
		OwnerDisplayName: safe.TrustedVarChar(security.RandString()),
		OwnerEmail:       safe.TrustedVarChar(security.RandString()),
		OwnerPassword:    safe.TrustedPassword(security.RandString()),
		Role:             s.st.DefaultRole,
	}
	bs, bsErr := json.Marshal(ev)
	require.NoError(s.T(), bsErr)
	u, urlErr := url.Parse(s.srv.URL + "/api/" + s.st.APIVersion + "/org")
	require.NoError(s.T(), urlErr)
	req, reqErr := http.NewRequest(http.MethodPost, u.String(), bytes.NewBuffer(bs))
	require.NoError(s.T(), reqErr)
	req.Header.Add(app.IDHeader, owner.ID.String())
	req.Header.Add(app.AuthorizationHeader, jwt.SignedStringToHeaderValue(ownerTok.Token))
	resp, postErr = s.c.Do(req)
	require.NoError(s.T(), postErr)
	require.Equal(s.T(), http.StatusForbidden, resp.StatusCode)
}

// TestPostAsRegularUser demonstrates that user auth cannot create an org.
func (s *OrgSuite) TestPostAsRegularUser() {
	conn, connErr := s.st.Master.Acquire(context.Background())
	require.NoError(s.T(), connErr)
	defer conn.Release()
	_, _, regularUser, oErr := app_testing.TestOrgAndUser(conn.Conn(), s.st)
	require.NoError(s.T(), oErr)
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
	require.Equal(s.T(), resp.StatusCode, http.StatusOK)
	defer resp.Body.Close()
	body, readErr := io.ReadAll(resp.Body)
	require.NoError(s.T(), readErr)
	var regularUserTok token.JSONToken
	umErr := json.Unmarshal(body, &regularUserTok)
	require.NoError(s.T(), umErr)
	require.NotEmpty(s.T(), regularUserTok.Token)

	ev := org.CreateEvent{
		Name:             safe.TrustedVarChar(security.RandString()),
		OwnerDisplayName: safe.TrustedVarChar(security.RandString()),
		OwnerEmail:       safe.TrustedVarChar(security.RandString()),
		OwnerPassword:    safe.TrustedPassword(security.RandString()),
		Role:             s.st.DefaultRole,
	}
	bs, bsErr := json.Marshal(ev)
	require.NoError(s.T(), bsErr)
	u, urlErr := url.Parse(s.srv.URL + "/api/" + s.st.APIVersion + "/org")
	require.NoError(s.T(), urlErr)
	req, reqErr := http.NewRequest(http.MethodPost, u.String(), bytes.NewBuffer(bs))
	require.NoError(s.T(), reqErr)
	req.Header.Add(app.IDHeader, regularUser.ID.String())
	req.Header.Add(app.AuthorizationHeader, jwt.SignedStringToHeaderValue(regularUserTok.Token))
	resp, postErr = s.c.Do(req)
	require.NoError(s.T(), postErr)
	require.Equal(s.T(), http.StatusForbidden, resp.StatusCode)
}

func (s *OrgSuite) TestPostMalformedCreateEvent() {
	evs := []org.CreateEvent{
		{
			Name:             safe.TrustedVarChar(""),
			OwnerDisplayName: safe.TrustedVarChar(security.RandString()),
			OwnerEmail:       safe.TrustedVarChar(security.RandString()),
			OwnerPassword:    safe.TrustedPassword(security.RandString()),
			Role:             s.st.DefaultRole,
		},
		{
			Name:             safe.TrustedVarChar(security.RandString()),
			OwnerDisplayName: safe.TrustedVarChar("    "),
			OwnerEmail:       safe.TrustedVarChar(security.RandString()),
			OwnerPassword:    safe.TrustedPassword(security.RandString()),
			Role:             s.st.DefaultRole,
		},
		{
			Name:             safe.TrustedVarChar(security.RandString()),
			OwnerDisplayName: safe.TrustedVarChar(security.RandString()),
			OwnerEmail:       safe.TrustedVarChar(""),
			OwnerPassword:    safe.TrustedPassword(security.RandString()),
			Role:             s.st.DefaultRole,
		},
		{
			Name:             safe.TrustedVarChar(security.RandString()),
			OwnerDisplayName: safe.TrustedVarChar(security.RandString()),
			OwnerEmail:       safe.TrustedVarChar(security.RandString()),
			OwnerPassword:    safe.TrustedPassword(" "),
			Role:             s.st.DefaultRole,
		},
	}

	for _, ev := range evs {
		bs, bsErr := json.Marshal(ev)
		require.NoError(s.T(), bsErr)
		u, urlErr := url.Parse(s.srv.URL + "/api/" + s.st.APIVersion + "/org")
		require.NoError(s.T(), urlErr)
		req, reqErr := http.NewRequest(http.MethodPost, u.String(), bytes.NewBuffer(bs))
		require.NoError(s.T(), reqErr)
		req.Header.Add(app.IDHeader, s.st.Root.ID.String())
		req.Header.Add(app.AuthorizationHeader, jwt.SignedStringToHeaderValue(s.tok.Token))
		resp, postErr := s.c.Do(req)
		require.NoError(s.T(), postErr)
		require.Equal(s.T(), http.StatusBadRequest, resp.StatusCode)
	}
}

func (s *OrgSuite) TestPostNoMatchingEvent() {
	u, urlErr := url.Parse(s.srv.URL + "/api/" + s.st.APIVersion + "/org")
	require.NoError(s.T(), urlErr)

	// make up a type that does not match any event
	type Unknown struct {
		S string `json:"s"`
	}

	ev := Unknown{S: "hello"}
	bs, bsErr := json.Marshal(ev)
	require.NoError(s.T(), bsErr)
	req, reqErr := http.NewRequest(http.MethodPost, u.String(), bytes.NewBuffer(bs))
	require.NoError(s.T(), reqErr)
	req.Header.Add(app.IDHeader, s.st.Root.ID.String())
	req.Header.Add(app.AuthorizationHeader, jwt.SignedStringToHeaderValue(s.tok.Token))
	resp, postErr := s.c.Do(req)
	require.NoError(s.T(), postErr)
	require.Equal(s.T(), http.StatusBadRequest, resp.StatusCode)
}

func (s *OrgSuite) TestPostConflict() {
	ev := org.CreateEvent{
		Name:             safe.TrustedVarChar(security.RandString()),
		OwnerDisplayName: safe.TrustedVarChar(security.RandString()),
		OwnerEmail:       safe.TrustedVarChar(security.RandString()),
		OwnerPassword:    safe.TrustedPassword(security.RandString()),
		Role:             s.st.DefaultRole,
	}
	bs, bsErr := json.Marshal(ev)
	require.NoError(s.T(), bsErr)
	u, urlErr := url.Parse(s.srv.URL + "/api/" + s.st.APIVersion + "/org")
	require.NoError(s.T(), urlErr)
	req, reqErr := http.NewRequest(http.MethodPost, u.String(), bytes.NewBuffer(bs))
	require.NoError(s.T(), reqErr)
	req.Header.Add(app.IDHeader, s.st.Root.ID.String())
	req.Header.Add(app.AuthorizationHeader, jwt.SignedStringToHeaderValue(s.tok.Token))
	resp, postErr := s.c.Do(req)
	require.NoError(s.T(), postErr)
	require.Equal(s.T(), http.StatusCreated, resp.StatusCode)

	// resend with org name already in use
	req, reqErr = http.NewRequest(http.MethodPost, u.String(), bytes.NewBuffer(bs))
	require.NoError(s.T(), reqErr)
	req.Header.Add(app.IDHeader, s.st.Root.ID.String())
	req.Header.Add(app.AuthorizationHeader, jwt.SignedStringToHeaderValue(s.tok.Token))
	resp, postErr = s.c.Do(req)
	require.NoError(s.T(), postErr)
	require.Equal(s.T(), http.StatusConflict, resp.StatusCode)
}
