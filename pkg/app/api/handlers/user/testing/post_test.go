package testing

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"

	"github.com/google/uuid"
	"github.com/grokloc/grokloc-apiserver/pkg/app"
	"github.com/grokloc/grokloc-apiserver/pkg/safe"
	"github.com/grokloc/grokloc-apiserver/pkg/security"

	"github.com/grokloc/grokloc-apiserver/pkg/app/admin/user"
	"github.com/grokloc/grokloc-apiserver/pkg/app/jwt"
	"github.com/grokloc/grokloc-apiserver/pkg/app/models"
	"github.com/stretchr/testify/require"
)

func (s *UserSuite) TestPostAsRoot() {
	conn, connErr := s.st.Master.Acquire(context.Background())
	require.NoError(s.T(), connErr)
	defer conn.Release()
	ev := user.CreateEvent{
		DisplayName: safe.TrustedVarChar(security.RandString()),
		Email:       safe.TrustedVarChar(security.RandString()),
		Org:         s.o.ID,
		Password:    safe.TrustedPassword(security.RandString()),
	}
	bs, bsErr := json.Marshal(ev)
	require.NoError(s.T(), bsErr)
	u, urlErr := url.Parse(s.srv.URL + app.APIPath + s.st.APIVersion + "/user")
	require.NoError(s.T(), urlErr)
	req, reqErr := http.NewRequest(http.MethodPost, u.String(), bytes.NewBuffer(bs))
	require.NoError(s.T(), reqErr)
	req.Header.Add(app.IDHeader, s.st.Root.ID.String())
	req.Header.Add(app.AuthorizationHeader, jwt.SignedStringToHeaderValue(s.tok.Token))
	resp, postErr := s.c.Do(req)
	require.NoError(s.T(), postErr)
	require.Equal(s.T(), http.StatusCreated, resp.StatusCode)
	decoder := json.NewDecoder(resp.Body)
	decoder.DisallowUnknownFields()
	var usr user.User
	dcErr := decoder.Decode(&usr)
	require.NoError(s.T(), dcErr)
	// parse the id from the location, then do a read on it
	// to verify
	location, locationErr := resp.Location()
	require.NoError(s.T(), locationErr)
	pathElts := strings.Split(location.Path, "/")
	require.True(s.T(), len(pathElts) != 0)
	id := pathElts[len(pathElts)-1]
	require.Equal(s.T(), usr.ID.String(), id)
	uRead, uReadErr := user.Read(context.Background(), conn.Conn(), s.st.VersionKey, usr.ID)
	require.NoError(s.T(), uReadErr)
	require.Equal(s.T(), usr.ID.String(), uRead.ID.String())
	require.Equal(s.T(), ev.DisplayName, uRead.DisplayName)
	require.Equal(s.T(), ev.Email, uRead.Email)
	// password will be derived when uploaded
	require.NotEqual(s.T(), ev.Password, uRead.Password)
	require.Equal(s.T(), ev.Org, uRead.Org)
	match, matchErr := security.VerifyPassword(ev.Password.String(), uRead.Password)
	require.NoError(s.T(), matchErr)
	require.True(s.T(), match)
}

func (s *UserSuite) TestPostAsOrgOwner() {
	conn, connErr := s.st.Master.Acquire(context.Background())
	require.NoError(s.T(), connErr)
	defer conn.Release()

	// try to create a user in owner's org
	ev := user.CreateEvent{
		DisplayName: safe.TrustedVarChar(security.RandString()),
		Email:       safe.TrustedVarChar(security.RandString()),
		Org:         s.o.ID,
		Password:    safe.TrustedPassword(security.RandString()),
	}
	bs, bsErr := json.Marshal(ev)
	require.NoError(s.T(), bsErr)
	u, urlErr := url.Parse(s.srv.URL + app.APIPath + s.st.APIVersion + "/user")
	require.NoError(s.T(), urlErr)
	req, reqErr := http.NewRequest(http.MethodPost, u.String(), bytes.NewBuffer(bs))
	require.NoError(s.T(), reqErr)
	req.Header.Add(app.IDHeader, s.owner.ID.String())
	req.Header.Add(app.AuthorizationHeader, jwt.SignedStringToHeaderValue(s.ownerTok.Token))
	resp, postErr := s.c.Do(req)
	require.NoError(s.T(), postErr)
	require.Equal(s.T(), http.StatusCreated, resp.StatusCode)
	// get response body (json serialized user)
	decoder := json.NewDecoder(resp.Body)
	decoder.DisallowUnknownFields()
	var usr user.User
	dcErr := decoder.Decode(&usr)
	require.NoError(s.T(), dcErr)
	// parse the id from the location, then do a read on it
	// to verify
	location, locationErr := resp.Location()
	require.NoError(s.T(), locationErr)
	pathElts := strings.Split(location.Path, "/")
	require.True(s.T(), len(pathElts) != 0)
	id := pathElts[len(pathElts)-1]
	require.Equal(s.T(), usr.ID.String(), id)
	uRead, uReadErr := user.Read(context.Background(), conn.Conn(), s.st.VersionKey, usr.ID)
	require.NoError(s.T(), uReadErr)
	require.Equal(s.T(), usr.ID.String(), uRead.ID.String())
	require.Equal(s.T(), ev.DisplayName, uRead.DisplayName)
	require.Equal(s.T(), ev.Email, uRead.Email)
	require.NotEqual(s.T(), ev.Password, uRead.Password)
	require.Equal(s.T(), ev.Org, uRead.Org)

	// try to have the org owner set a user in an org not theirs
	ev.Org = s.st.Org.ID // root org
	bs, bsErr = json.Marshal(ev)
	require.NoError(s.T(), bsErr)
	req, reqErr = http.NewRequest(http.MethodPost, u.String(), bytes.NewBuffer(bs))
	require.NoError(s.T(), reqErr)
	req.Header.Add(app.IDHeader, s.owner.ID.String())
	req.Header.Add(app.AuthorizationHeader, jwt.SignedStringToHeaderValue(s.ownerTok.Token))
	resp, postErr = s.c.Do(req)
	require.NoError(s.T(), postErr)
	require.Equal(s.T(), http.StatusForbidden, resp.StatusCode)
}

// TestPostAsRegularUser demonstrates that user auth cannot create a user.
func (s *UserSuite) TestPostAsRegularUser() {
	ev := user.CreateEvent{
		DisplayName: safe.TrustedVarChar(security.RandString()),
		Email:       safe.TrustedVarChar(security.RandString()),
		Org:         s.o.ID,
		Password:    safe.TrustedPassword(security.RandString()),
	}
	bs, bsErr := json.Marshal(ev)
	require.NoError(s.T(), bsErr)
	u, urlErr := url.Parse(s.srv.URL + app.APIPath + s.st.APIVersion + "/user")
	require.NoError(s.T(), urlErr)
	req, reqErr := http.NewRequest(http.MethodPost, u.String(), bytes.NewBuffer(bs))
	require.NoError(s.T(), reqErr)
	req.Header.Add(app.IDHeader, s.regularUser.ID.String())
	req.Header.Add(app.AuthorizationHeader, jwt.SignedStringToHeaderValue(s.regularUserTok.Token))
	resp, postErr := s.c.Do(req)
	require.NoError(s.T(), postErr)
	require.Equal(s.T(), http.StatusForbidden, resp.StatusCode)
}

func (s *UserSuite) TestPostMalformedCreateEvent() {
	var empty uuid.UUID
	evs := []user.CreateEvent{
		{
			DisplayName: safe.TrustedVarChar(""),
			Email:       safe.TrustedVarChar(security.RandString()),
			Org:         models.NewID(),
			Password:    safe.TrustedPassword(security.RandString()),
		},
		{
			DisplayName: safe.TrustedVarChar(security.RandString()),
			Email:       safe.TrustedVarChar("  "),
			Org:         models.NewID(),
			Password:    safe.TrustedPassword(security.RandString()),
		},
		{
			DisplayName: safe.TrustedVarChar(security.RandString()),
			Email:       safe.TrustedVarChar(security.RandString()),
			Org:         models.ID(empty),
			Password:    safe.TrustedPassword(security.RandString()),
		},
		{
			DisplayName: safe.TrustedVarChar(security.RandString()),
			Email:       safe.TrustedVarChar(security.RandString()),
			Org:         models.NewID(),
			Password:    safe.TrustedPassword(" "),
		},
	}

	for _, ev := range evs {
		bs, bsErr := json.Marshal(ev)
		require.NoError(s.T(), bsErr)
		u, urlErr := url.Parse(s.srv.URL + app.APIPath + s.st.APIVersion + "/user")
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

func (s *UserSuite) TestPostNoMatchingEvent() {
	u, urlErr := url.Parse(s.srv.URL + app.APIPath + s.st.APIVersion + "/user")
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

func (s *UserSuite) TestPostConflict() {
	ev := user.CreateEvent{
		DisplayName: safe.TrustedVarChar(security.RandString()),
		Email:       safe.TrustedVarChar(security.RandString()),
		Org:         s.o.ID,
		Password:    safe.TrustedPassword(security.RandString()),
	}
	bs, bsErr := json.Marshal(ev)
	require.NoError(s.T(), bsErr)
	u, urlErr := url.Parse(s.srv.URL + app.APIPath + s.st.APIVersion + "/user")
	require.NoError(s.T(), urlErr)
	req, reqErr := http.NewRequest(http.MethodPost, u.String(), bytes.NewBuffer(bs))
	require.NoError(s.T(), reqErr)
	req.Header.Add(app.IDHeader, s.st.Root.ID.String())
	req.Header.Add(app.AuthorizationHeader, jwt.SignedStringToHeaderValue(s.tok.Token))
	resp, postErr := s.c.Do(req)
	require.NoError(s.T(), postErr)
	require.Equal(s.T(), http.StatusCreated, resp.StatusCode)

	// resend with user email already in use in org
	req, reqErr = http.NewRequest(http.MethodPost, u.String(), bytes.NewBuffer(bs))
	require.NoError(s.T(), reqErr)
	req.Header.Add(app.IDHeader, s.st.Root.ID.String())
	req.Header.Add(app.AuthorizationHeader, jwt.SignedStringToHeaderValue(s.tok.Token))
	resp, postErr = s.c.Do(req)
	require.NoError(s.T(), postErr)
	require.Equal(s.T(), http.StatusConflict, resp.StatusCode)
}
