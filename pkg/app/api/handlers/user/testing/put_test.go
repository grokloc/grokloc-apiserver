package testing

import (
	"bytes"
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
	"github.com/grokloc/grokloc-apiserver/pkg/safe"
	"github.com/grokloc/grokloc-apiserver/pkg/security"
	"github.com/stretchr/testify/require"
)

func (s *UserSuite) TestPutAsRoot() {
	conn, connErr := s.st.Master.Acquire(context.Background())
	require.NoError(s.T(), connErr)
	defer conn.Release()
	_, _, regularUser, oErr := app_testing.TestOrgAndUser(conn.Conn(), s.st)
	require.NoError(s.T(), oErr)
	u, urlErr := url.Parse(s.srv.URL + app.APIPath + s.st.APIVersion + "/user/" + regularUser.ID.String())
	require.NoError(s.T(), urlErr)

	// update api secret
	previousAPISecret := regularUser.APISecret
	evUpdateAPISecret := user.UpdateAPISecretEvent{
		GenerateAPISecret: true,
	}
	bs, bsErr := json.Marshal(evUpdateAPISecret)
	require.NoError(s.T(), bsErr)
	req, reqErr := http.NewRequest(http.MethodPut, u.String(), bytes.NewBuffer(bs))
	require.NoError(s.T(), reqErr)
	req.Header.Add(app.IDHeader, s.st.Root.ID.String())
	req.Header.Add(app.AuthorizationHeader, jwt.SignedStringToHeaderValue(s.tok.Token))
	resp, putErr := s.c.Do(req)
	require.NoError(s.T(), putErr)
	require.Equal(s.T(), http.StatusOK, resp.StatusCode)

	// update display name
	newDisplayName := safe.TrustedVarChar(security.RandString())
	evUpdateDisplayName := user.UpdateDisplayNameEvent{
		DisplayName: newDisplayName,
	}
	bs, bsErr = json.Marshal(evUpdateDisplayName)
	require.NoError(s.T(), bsErr)
	req, reqErr = http.NewRequest(http.MethodPut, u.String(), bytes.NewBuffer(bs))
	require.NoError(s.T(), reqErr)
	req.Header.Add(app.IDHeader, s.st.Root.ID.String())
	req.Header.Add(app.AuthorizationHeader, jwt.SignedStringToHeaderValue(s.tok.Token))
	resp, putErr = s.c.Do(req)
	require.NoError(s.T(), putErr)
	require.Equal(s.T(), http.StatusOK, resp.StatusCode)

	// update password - root cannot do this
	newPassword := safe.TrustedPassword(security.RandString())
	evUpdatePassword := user.UpdatePasswordEvent{
		Password: newPassword,
	}
	bs, bsErr = json.Marshal(evUpdatePassword)
	require.NoError(s.T(), bsErr)
	req, reqErr = http.NewRequest(http.MethodPut, u.String(), bytes.NewBuffer(bs))
	require.NoError(s.T(), reqErr)
	req.Header.Add(app.IDHeader, s.st.Root.ID.String())
	req.Header.Add(app.AuthorizationHeader, jwt.SignedStringToHeaderValue(s.tok.Token))
	resp, putErr = s.c.Do(req)
	require.NoError(s.T(), putErr)
	require.Equal(s.T(), http.StatusForbidden, resp.StatusCode)

	// update status
	evUpdateStatus := user.UpdateStatusEvent{
		Status: models.StatusInactive,
	}
	bs, bsErr = json.Marshal(evUpdateStatus)
	require.NoError(s.T(), bsErr)
	req, reqErr = http.NewRequest(http.MethodPut, u.String(), bytes.NewBuffer(bs))
	require.NoError(s.T(), reqErr)
	req.Header.Add(app.IDHeader, s.st.Root.ID.String())
	req.Header.Add(app.AuthorizationHeader, jwt.SignedStringToHeaderValue(s.tok.Token))
	resp, putErr = s.c.Do(req)
	require.NoError(s.T(), putErr)
	require.Equal(s.T(), http.StatusOK, resp.StatusCode)

	// get response body (json serialized user)
	decoder := json.NewDecoder(resp.Body)
	decoder.DisallowUnknownFields()
	var usr user.User
	dcErr := decoder.Decode(&usr)
	require.NoError(s.T(), dcErr)

	require.Equal(s.T(), models.StatusInactive, usr.Meta.Status)
	require.Equal(s.T(), newDisplayName, usr.DisplayName)
	require.NotEqual(s.T(), previousAPISecret, usr.APISecret)
	uRead, uReadErr := user.Read(context.Background(), conn.Conn(), s.st.VersionKey, usr.ID)
	require.NoError(s.T(), uReadErr)
	require.Equal(s.T(), models.StatusInactive, uRead.Meta.Status)
	require.Equal(s.T(), newDisplayName, uRead.DisplayName)
	require.NotEqual(s.T(), previousAPISecret, uRead.APISecret)
}

func (s *UserSuite) TestPutAsOrgOwner() {
	// create new org, regularUser to test these updates
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
	require.Equal(s.T(), resp.StatusCode, http.StatusOK)
	defer resp.Body.Close()
	body, readErr := io.ReadAll(resp.Body)
	require.NoError(s.T(), readErr)
	var ownerTok token.JSONToken
	umErr := json.Unmarshal(body, &ownerTok)
	require.NoError(s.T(), umErr)
	require.NotEmpty(s.T(), ownerTok.Token)

	u, urlErr := url.Parse(s.srv.URL + app.APIPath + s.st.APIVersion + "/user/" + regularUser.ID.String())
	require.NoError(s.T(), urlErr)

	// update api secret
	previousAPISecret := regularUser.APISecret
	evUpdateAPISecret := user.UpdateAPISecretEvent{
		GenerateAPISecret: true,
	}
	bs, bsErr := json.Marshal(evUpdateAPISecret)
	require.NoError(s.T(), bsErr)
	req, reqErr := http.NewRequest(http.MethodPut, u.String(), bytes.NewBuffer(bs))
	require.NoError(s.T(), reqErr)
	req.Header.Add(app.IDHeader, owner.ID.String())
	req.Header.Add(app.AuthorizationHeader, jwt.SignedStringToHeaderValue(ownerTok.Token))
	resp, putErr := s.c.Do(req)
	require.NoError(s.T(), putErr)
	require.Equal(s.T(), http.StatusOK, resp.StatusCode)

	// update display name
	newDisplayName := safe.TrustedVarChar(security.RandString())
	evUpdateDisplayName := user.UpdateDisplayNameEvent{
		DisplayName: newDisplayName,
	}
	bs, bsErr = json.Marshal(evUpdateDisplayName)
	require.NoError(s.T(), bsErr)
	req, reqErr = http.NewRequest(http.MethodPut, u.String(), bytes.NewBuffer(bs))
	require.NoError(s.T(), reqErr)
	req.Header.Add(app.IDHeader, owner.ID.String())
	req.Header.Add(app.AuthorizationHeader, jwt.SignedStringToHeaderValue(ownerTok.Token))
	resp, putErr = s.c.Do(req)
	require.NoError(s.T(), putErr)
	require.Equal(s.T(), http.StatusOK, resp.StatusCode)

	// update password - org owner cannot do this
	newPassword := safe.TrustedPassword(security.RandString())
	evUpdatePassword := user.UpdatePasswordEvent{
		Password: newPassword,
	}
	bs, bsErr = json.Marshal(evUpdatePassword)
	require.NoError(s.T(), bsErr)
	req, reqErr = http.NewRequest(http.MethodPut, u.String(), bytes.NewBuffer(bs))
	require.NoError(s.T(), reqErr)
	req.Header.Add(app.IDHeader, owner.ID.String())
	req.Header.Add(app.AuthorizationHeader, jwt.SignedStringToHeaderValue(ownerTok.Token))
	resp, putErr = s.c.Do(req)
	require.NoError(s.T(), putErr)
	require.Equal(s.T(), http.StatusForbidden, resp.StatusCode)

	// update status
	evUpdateStatus := user.UpdateStatusEvent{
		Status: models.StatusInactive,
	}
	bs, bsErr = json.Marshal(evUpdateStatus)
	require.NoError(s.T(), bsErr)
	req, reqErr = http.NewRequest(http.MethodPut, u.String(), bytes.NewBuffer(bs))
	require.NoError(s.T(), reqErr)
	req.Header.Add(app.IDHeader, owner.ID.String())
	req.Header.Add(app.AuthorizationHeader, jwt.SignedStringToHeaderValue(ownerTok.Token))
	resp, putErr = s.c.Do(req)
	require.NoError(s.T(), putErr)
	require.Equal(s.T(), http.StatusOK, resp.StatusCode)

	// get response body (json serialized user)
	decoder := json.NewDecoder(resp.Body)
	decoder.DisallowUnknownFields()
	var usr user.User
	dcErr := decoder.Decode(&usr)
	require.NoError(s.T(), dcErr)

	require.Equal(s.T(), models.StatusInactive, usr.Meta.Status)
	require.Equal(s.T(), newDisplayName, usr.DisplayName)
	require.NotEqual(s.T(), previousAPISecret, usr.APISecret)
	uRead, uReadErr := user.Read(context.Background(), conn.Conn(), s.st.VersionKey, usr.ID)
	require.NoError(s.T(), uReadErr)
	require.Equal(s.T(), models.StatusInactive, uRead.Meta.Status)
	require.Equal(s.T(), newDisplayName, uRead.DisplayName)
	require.NotEqual(s.T(), previousAPISecret, uRead.APISecret)

	// try to put to a user (root) that org owner has no permission to access
	u, urlErr = url.Parse(s.srv.URL + app.APIPath + s.st.APIVersion + "/user/" + s.st.Root.ID.String())
	require.NoError(s.T(), urlErr)
	evUpdateAPISecret = user.UpdateAPISecretEvent{
		GenerateAPISecret: true,
	}
	bs, bsErr = json.Marshal(evUpdateAPISecret)
	require.NoError(s.T(), bsErr)
	req, reqErr = http.NewRequest(http.MethodPut, u.String(), bytes.NewBuffer(bs))
	require.NoError(s.T(), reqErr)
	req.Header.Add(app.IDHeader, owner.ID.String())
	req.Header.Add(app.AuthorizationHeader, jwt.SignedStringToHeaderValue(ownerTok.Token))
	resp, putErr = s.c.Do(req)
	require.NoError(s.T(), putErr)
	require.Equal(s.T(), http.StatusForbidden, resp.StatusCode)
}

func (s *UserSuite) TestPutAsRegularUser() {
	// create new regularUser to test these updates
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

	u, urlErr := url.Parse(s.srv.URL + app.APIPath + s.st.APIVersion + "/user/" + regularUser.ID.String())
	require.NoError(s.T(), urlErr)

	// update status - user cannot change their own status
	evUpdateStatus := user.UpdateStatusEvent{
		Status: models.StatusInactive,
	}
	bs, bsErr := json.Marshal(evUpdateStatus)
	require.NoError(s.T(), bsErr)
	req, reqErr := http.NewRequest(http.MethodPut, u.String(), bytes.NewBuffer(bs))
	require.NoError(s.T(), reqErr)
	req.Header.Add(app.IDHeader, regularUser.ID.String())
	req.Header.Add(app.AuthorizationHeader, jwt.SignedStringToHeaderValue(regularUserTok.Token))
	resp, putErr := s.c.Do(req)
	require.NoError(s.T(), putErr)
	require.Equal(s.T(), http.StatusForbidden, resp.StatusCode)

	// update api secret
	previousAPISecret := regularUser.APISecret
	evUpdateAPISecret := user.UpdateAPISecretEvent{
		GenerateAPISecret: true,
	}
	bs, bsErr = json.Marshal(evUpdateAPISecret)
	require.NoError(s.T(), bsErr)
	req, reqErr = http.NewRequest(http.MethodPut, u.String(), bytes.NewBuffer(bs))
	require.NoError(s.T(), reqErr)
	req.Header.Add(app.IDHeader, regularUser.ID.String())
	req.Header.Add(app.AuthorizationHeader, jwt.SignedStringToHeaderValue(regularUserTok.Token))
	resp, putErr = s.c.Do(req)
	require.NoError(s.T(), putErr)
	require.Equal(s.T(), http.StatusOK, resp.StatusCode)

	// update display name
	newDisplayName := safe.TrustedVarChar(security.RandString())
	evUpdateDisplayName := user.UpdateDisplayNameEvent{
		DisplayName: newDisplayName,
	}
	bs, bsErr = json.Marshal(evUpdateDisplayName)
	require.NoError(s.T(), bsErr)
	req, reqErr = http.NewRequest(http.MethodPut, u.String(), bytes.NewBuffer(bs))
	require.NoError(s.T(), reqErr)
	req.Header.Add(app.IDHeader, regularUser.ID.String())
	req.Header.Add(app.AuthorizationHeader, jwt.SignedStringToHeaderValue(regularUserTok.Token))
	resp, putErr = s.c.Do(req)
	require.NoError(s.T(), putErr)
	// bad request because the token used has not been refreshed
	// since the API Secret was changed!
	require.Equal(s.T(), http.StatusUnauthorized, resp.StatusCode)

	// try to update display name again, but first get a new token
	// first, refresh regularUser to get the new API Secret
	var refreshErr error
	regularUser, refreshErr = user.Read(context.Background(), conn.Conn(), s.st.VersionKey, regularUser.ID)
	require.NoError(s.T(), refreshErr)
	// get a new token
	regularUserTokenRequest = jwt.EncodeTokenRequest(regularUser.ID, regularUser.APISecret.String())
	regularUserReq = http.Request{
		URL:    tokenReqUrl,
		Method: http.MethodPost,
		Header: map[string][]string{
			app.IDHeader:           {regularUser.ID.String()},
			app.TokenRequestHeader: {regularUserTokenRequest},
		},
	}
	resp, postErr = s.c.Do(&regularUserReq)
	require.NoError(s.T(), postErr)
	defer resp.Body.Close()
	body, readErr = io.ReadAll(resp.Body)
	require.NoError(s.T(), readErr)
	umErr = json.Unmarshal(body, &regularUserTok)
	require.NoError(s.T(), umErr)
	require.NotEmpty(s.T(), regularUserTok.Token)
	// now try to update display name again
	bs, bsErr = json.Marshal(evUpdateDisplayName)
	require.NoError(s.T(), bsErr)
	req, reqErr = http.NewRequest(http.MethodPut, u.String(), bytes.NewBuffer(bs))
	require.NoError(s.T(), reqErr)
	req.Header.Add(app.IDHeader, regularUser.ID.String())
	req.Header.Add(app.AuthorizationHeader, jwt.SignedStringToHeaderValue(regularUserTok.Token))
	resp, putErr = s.c.Do(req)
	require.NoError(s.T(), putErr)
	require.Equal(s.T(), http.StatusOK, resp.StatusCode)

	// update password
	newPassword := safe.TrustedPassword(security.RandString())
	evUpdatePassword := user.UpdatePasswordEvent{
		Password: newPassword,
	}
	bs, bsErr = json.Marshal(evUpdatePassword)
	require.NoError(s.T(), bsErr)
	req, reqErr = http.NewRequest(http.MethodPut, u.String(), bytes.NewBuffer(bs))
	require.NoError(s.T(), reqErr)
	req.Header.Add(app.IDHeader, regularUser.ID.String())
	req.Header.Add(app.AuthorizationHeader, jwt.SignedStringToHeaderValue(regularUserTok.Token))
	resp, putErr = s.c.Do(req)
	require.NoError(s.T(), putErr)
	require.Equal(s.T(), http.StatusOK, resp.StatusCode)

	// get response body (json serialized user)
	decoder := json.NewDecoder(resp.Body)
	decoder.DisallowUnknownFields()
	var usr user.User
	dcErr := decoder.Decode(&usr)
	require.NoError(s.T(), dcErr)

	require.Equal(s.T(), models.StatusActive, usr.Meta.Status)
	require.Equal(s.T(), newDisplayName, usr.DisplayName)
	require.NotEqual(s.T(), previousAPISecret, usr.APISecret)
	uRead, uReadErr := user.Read(context.Background(), conn.Conn(), s.st.VersionKey, usr.ID)
	require.NoError(s.T(), uReadErr)
	require.Equal(s.T(), models.StatusActive, uRead.Meta.Status)
	require.Equal(s.T(), newDisplayName, uRead.DisplayName)
	require.NotEqual(s.T(), previousAPISecret, uRead.APISecret)
	// uRead has password populated, usr doesn't
	match, matchErr := security.VerifyPassword(newPassword.String(), uRead.Password)
	require.NoError(s.T(), matchErr)
	require.True(s.T(), match)

	// try to put to a user (root) that regular user has no permission to access
	u, urlErr = url.Parse(s.srv.URL + app.APIPath + s.st.APIVersion + "/user/" + s.st.Root.ID.String())
	require.NoError(s.T(), urlErr)
	evUpdateAPISecret = user.UpdateAPISecretEvent{
		GenerateAPISecret: true,
	}
	bs, bsErr = json.Marshal(evUpdateAPISecret)
	require.NoError(s.T(), bsErr)
	req, reqErr = http.NewRequest(http.MethodPut, u.String(), bytes.NewBuffer(bs))
	require.NoError(s.T(), reqErr)
	req.Header.Add(app.IDHeader, regularUser.ID.String())
	req.Header.Add(app.AuthorizationHeader, jwt.SignedStringToHeaderValue(regularUserTok.Token))
	resp, putErr = s.c.Do(req)
	require.NoError(s.T(), putErr)
	require.Equal(s.T(), http.StatusForbidden, resp.StatusCode)
}

func (s *UserSuite) TestPutNotFound() {
	u, urlErr := url.Parse(s.srv.URL + app.APIPath + s.st.APIVersion + "/user/" + models.NewID().String())
	require.NoError(s.T(), urlErr)
	evUpdateAPISecret := user.UpdateAPISecretEvent{
		GenerateAPISecret: true,
	}
	bs, bsErr := json.Marshal(evUpdateAPISecret)
	require.NoError(s.T(), bsErr)
	req, reqErr := http.NewRequest(http.MethodPut, u.String(), bytes.NewBuffer(bs))
	require.NoError(s.T(), reqErr)
	req.Header.Add(app.IDHeader, s.st.Root.ID.String())
	req.Header.Add(app.AuthorizationHeader, jwt.SignedStringToHeaderValue(s.tok.Token))
	resp, putErr := s.c.Do(req)
	require.NoError(s.T(), putErr)
	require.Equal(s.T(), http.StatusNotFound, resp.StatusCode)
}

func (s *UserSuite) TestPutMalformedUpdateEvents() {
	conn, connErr := s.st.Master.Acquire(context.Background())
	require.NoError(s.T(), connErr)
	defer conn.Release()
	_, _, regularUser, oErr := app_testing.TestOrgAndUser(conn.Conn(), s.st)
	require.NoError(s.T(), oErr)
	u, urlErr := url.Parse(s.srv.URL + app.APIPath + s.st.APIVersion + "/user/" + regularUser.ID.String())
	require.NoError(s.T(), urlErr)

	// bad api secret update
	evUpdateAPISecret := user.UpdateAPISecretEvent{
		GenerateAPISecret: false,
	}
	bs, bsErr := json.Marshal(evUpdateAPISecret)
	require.NoError(s.T(), bsErr)
	req, reqErr := http.NewRequest(http.MethodPut, u.String(), bytes.NewBuffer(bs))
	require.NoError(s.T(), reqErr)
	req.Header.Add(app.IDHeader, s.st.Root.ID.String())
	req.Header.Add(app.AuthorizationHeader, jwt.SignedStringToHeaderValue(s.tok.Token))
	resp, putErr := s.c.Do(req)
	require.NoError(s.T(), putErr)
	require.Equal(s.T(), http.StatusBadRequest, resp.StatusCode)

	// bad display name update
	evUpdateDisplayName := user.UpdateDisplayNameEvent{
		DisplayName: safe.TrustedVarChar(""),
	}
	bs, bsErr = json.Marshal(evUpdateDisplayName)
	require.NoError(s.T(), bsErr)
	req, reqErr = http.NewRequest(http.MethodPut, u.String(), bytes.NewBuffer(bs))
	require.NoError(s.T(), reqErr)
	req.Header.Add(app.IDHeader, s.st.Root.ID.String())
	req.Header.Add(app.AuthorizationHeader, jwt.SignedStringToHeaderValue(s.tok.Token))
	resp, putErr = s.c.Do(req)
	require.NoError(s.T(), putErr)
	require.Equal(s.T(), http.StatusBadRequest, resp.StatusCode)

	// bad status update
	evUpdateStatus := user.UpdateStatusEvent{
		Status: models.StatusNone,
	}
	bs, bsErr = json.Marshal(evUpdateStatus)
	require.NoError(s.T(), bsErr)
	req, reqErr = http.NewRequest(http.MethodPut, u.String(), bytes.NewBuffer(bs))
	require.NoError(s.T(), reqErr)
	req.Header.Add(app.IDHeader, s.st.Root.ID.String())
	req.Header.Add(app.AuthorizationHeader, jwt.SignedStringToHeaderValue(s.tok.Token))
	resp, putErr = s.c.Do(req)
	require.NoError(s.T(), putErr)
	require.Equal(s.T(), http.StatusBadRequest, resp.StatusCode)

	// updating password can only be tested by regularUser
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
	defer resp.Body.Close()
	body, readErr := io.ReadAll(resp.Body)
	require.NoError(s.T(), readErr)
	var regularUserTok token.JSONToken
	umErr := json.Unmarshal(body, &regularUserTok)
	require.NoError(s.T(), umErr)
	require.NotEmpty(s.T(), regularUserTok.Token)

	// bad password update
	evUpdatePassword := user.UpdatePasswordEvent{
		Password: safe.TrustedPassword(""),
	}
	bs, bsErr = json.Marshal(evUpdatePassword)
	require.NoError(s.T(), bsErr)
	req, reqErr = http.NewRequest(http.MethodPut, u.String(), bytes.NewBuffer(bs))
	require.NoError(s.T(), reqErr)
	req.Header.Add(app.IDHeader, s.st.Root.ID.String())
	req.Header.Add(app.AuthorizationHeader, jwt.SignedStringToHeaderValue(s.tok.Token))
	resp, putErr = s.c.Do(req)
	require.NoError(s.T(), putErr)
	require.Equal(s.T(), http.StatusBadRequest, resp.StatusCode)
}

func (s *UserSuite) TestPutNoMatchingEvent() {
	conn, connErr := s.st.Master.Acquire(context.Background())
	require.NoError(s.T(), connErr)
	defer conn.Release()
	// create user to PUT to
	_, _, regularUser, oErr := app_testing.TestOrgAndUser(conn.Conn(), s.st)
	require.NoError(s.T(), oErr)

	u, urlErr := url.Parse(s.srv.URL + app.APIPath + s.st.APIVersion + "/user/" + regularUser.ID.String())
	require.NoError(s.T(), urlErr)

	// make up a type that does not match any event
	type Unknown struct {
		S string `json:"s"`
	}

	ev := Unknown{S: "hello"}
	bs, bsErr := json.Marshal(ev)
	require.NoError(s.T(), bsErr)
	req, reqErr := http.NewRequest(http.MethodPut, u.String(), bytes.NewBuffer(bs))
	require.NoError(s.T(), reqErr)
	req.Header.Add(app.IDHeader, s.st.Root.ID.String())
	req.Header.Add(app.AuthorizationHeader, jwt.SignedStringToHeaderValue(s.tok.Token))
	resp, putErr := s.c.Do(req)
	require.NoError(s.T(), putErr)
	require.Equal(s.T(), http.StatusBadRequest, resp.StatusCode)
}
