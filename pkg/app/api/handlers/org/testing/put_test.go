package testing

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/url"

	"github.com/google/uuid"
	"github.com/grokloc/grokloc-apiserver/pkg/app"
	"github.com/grokloc/grokloc-apiserver/pkg/app/admin/org"
	"github.com/grokloc/grokloc-apiserver/pkg/app/jwt"
	"github.com/grokloc/grokloc-apiserver/pkg/app/models"
	app_testing "github.com/grokloc/grokloc-apiserver/pkg/app/testing"
	"github.com/stretchr/testify/require"
)

func (s *OrgSuite) TestPutAsRoot() {
	conn, connErr := s.st.Master.Acquire(context.Background())
	require.NoError(s.T(), connErr)
	defer conn.Release()
	// create an org to PUT to
	o, _, regularUser, oErr := app_testing.TestOrgAndUser(conn.Conn(), s.st)
	require.NoError(s.T(), oErr)

	u, urlErr := url.Parse(s.srv.URL + app.APIPath + s.st.APIVersion + "/org/" + o.ID.String())
	require.NoError(s.T(), urlErr)

	// set to inactive
	evStatus := org.UpdateStatusEvent{
		Status: models.StatusInactive,
	}
	bs, bsErr := json.Marshal(evStatus)
	require.NoError(s.T(), bsErr)
	req, reqErr := http.NewRequest(http.MethodPut, u.String(), bytes.NewBuffer(bs))
	require.NoError(s.T(), reqErr)
	req.Header.Add(app.IDHeader, s.st.Root.ID.String())
	req.Header.Add(app.AuthorizationHeader, jwt.SignedStringToHeaderValue(s.tok.Token))
	resp, putErr := s.c.Do(req)
	require.NoError(s.T(), putErr)
	require.Equal(s.T(), http.StatusOK, resp.StatusCode)
	// get response body (json serialized org)
	decoder := json.NewDecoder(resp.Body)
	decoder.DisallowUnknownFields()
	var oRead0 org.Org
	dcErr := decoder.Decode(&oRead0)
	require.NoError(s.T(), dcErr)
	require.Equal(s.T(), models.StatusInactive, oRead0.Meta.Status)

	// set owner to be regularUser
	evOwner := org.UpdateOwnerEvent{
		Owner: regularUser.ID,
	}
	bs, bsErr = json.Marshal(evOwner)
	require.NoError(s.T(), bsErr)
	req, reqErr = http.NewRequest(http.MethodPut, u.String(), bytes.NewBuffer(bs))
	require.NoError(s.T(), reqErr)
	req.Header.Add(app.IDHeader, s.st.Root.ID.String())
	req.Header.Add(app.AuthorizationHeader, jwt.SignedStringToHeaderValue(s.tok.Token))
	resp, putErr = s.c.Do(req)
	require.NoError(s.T(), putErr)
	require.Equal(s.T(), http.StatusOK, resp.StatusCode)
	// get response body (json serialized org)
	decoder = json.NewDecoder(resp.Body)
	decoder.DisallowUnknownFields()
	var oRead1 org.Org
	dcErr = decoder.Decode(&oRead1)
	require.NoError(s.T(), dcErr)
	require.Equal(s.T(), regularUser.ID, oRead1.Owner)

	// try nonexistant user as candidate owner
	require.NoError(s.T(), urlErr)
	evOwner = org.UpdateOwnerEvent{
		Owner: models.NewID(),
	}
	bs, bsErr = json.Marshal(evOwner)
	require.NoError(s.T(), bsErr)
	req, reqErr = http.NewRequest(http.MethodPut, u.String(), bytes.NewBuffer(bs))
	require.NoError(s.T(), reqErr)
	req.Header.Add(app.IDHeader, s.st.Root.ID.String())
	req.Header.Add(app.AuthorizationHeader, jwt.SignedStringToHeaderValue(s.tok.Token))
	resp, putErr = s.c.Do(req)
	require.NoError(s.T(), putErr)
	require.Equal(s.T(), http.StatusBadRequest, resp.StatusCode)

	// try nonexistant org
	u, urlErr = url.Parse(s.srv.URL + app.APIPath + s.st.APIVersion + "/org/" + models.NewID().String())
	require.NoError(s.T(), urlErr)
	evOwner = org.UpdateOwnerEvent{
		Owner: regularUser.ID,
	}
	bs, bsErr = json.Marshal(evOwner)
	require.NoError(s.T(), bsErr)
	req, reqErr = http.NewRequest(http.MethodPut, u.String(), bytes.NewBuffer(bs))
	require.NoError(s.T(), reqErr)
	req.Header.Add(app.IDHeader, s.st.Root.ID.String())
	req.Header.Add(app.AuthorizationHeader, jwt.SignedStringToHeaderValue(s.tok.Token))
	resp, putErr = s.c.Do(req)
	require.NoError(s.T(), putErr)
	require.Equal(s.T(), http.StatusNotFound, resp.StatusCode)
}

// TestPutAsOrgOwner demonstrates that org owner auth cannot update an org.
func (s *OrgSuite) TestPutAsOrgOwner() {
	// try to set to inactive
	ev := org.UpdateStatusEvent{
		Status: models.StatusInactive,
	}
	bs, bsErr := json.Marshal(ev)
	require.NoError(s.T(), bsErr)
	u, urlErr := url.Parse(s.srv.URL + app.APIPath + s.st.APIVersion + "/org/" + s.o.ID.String())
	require.NoError(s.T(), urlErr)
	req, reqErr := http.NewRequest(http.MethodPut, u.String(), bytes.NewBuffer(bs))
	require.NoError(s.T(), reqErr)
	req.Header.Add(app.IDHeader, s.owner.ID.String())
	req.Header.Add(app.AuthorizationHeader, jwt.SignedStringToHeaderValue(s.ownerTok.Token))
	resp, putErr := s.c.Do(req)
	require.NoError(s.T(), putErr)
	require.Equal(s.T(), http.StatusForbidden, resp.StatusCode)
}

// TestPutAsRegularUser demonstrates that user auth cannot update an org.
func (s *OrgSuite) TestPutAsRegularUser() {
	// try to set to inactive
	ev := org.UpdateStatusEvent{
		Status: models.StatusInactive,
	}
	bs, bsErr := json.Marshal(ev)
	require.NoError(s.T(), bsErr)
	u, urlErr := url.Parse(s.srv.URL + app.APIPath + s.st.APIVersion + "/org/" + s.o.ID.String())
	require.NoError(s.T(), urlErr)
	req, reqErr := http.NewRequest(http.MethodPut, u.String(), bytes.NewBuffer(bs))
	require.NoError(s.T(), reqErr)
	req.Header.Add(app.IDHeader, s.regularUser.ID.String())
	req.Header.Add(app.AuthorizationHeader, jwt.SignedStringToHeaderValue(s.regularUserTok.Token))
	resp, putErr := s.c.Do(req)
	require.NoError(s.T(), putErr)
	require.Equal(s.T(), http.StatusForbidden, resp.StatusCode)
}

func (s *OrgSuite) TestPutNotFound() {
	u, urlErr := url.Parse(s.srv.URL + app.APIPath + s.st.APIVersion + "/org/" + models.NewID().String())
	require.NoError(s.T(), urlErr)

	// set to inactive
	evStatus := org.UpdateStatusEvent{
		Status: models.StatusInactive,
	}
	bs, bsErr := json.Marshal(evStatus)
	require.NoError(s.T(), bsErr)
	req, reqErr := http.NewRequest(http.MethodPut, u.String(), bytes.NewBuffer(bs))
	require.NoError(s.T(), reqErr)
	req.Header.Add(app.IDHeader, s.st.Root.ID.String())
	req.Header.Add(app.AuthorizationHeader, jwt.SignedStringToHeaderValue(s.tok.Token))
	resp, putErr := s.c.Do(req)
	require.NoError(s.T(), putErr)
	require.Equal(s.T(), http.StatusNotFound, resp.StatusCode)
}

func (s *OrgSuite) TestPutMalformedUpdateEvents() {
	u, urlErr := url.Parse(s.srv.URL + app.APIPath + s.st.APIVersion + "/org/" + s.o.ID.String())
	require.NoError(s.T(), urlErr)

	// bad status update
	evStatus := org.UpdateStatusEvent{
		Status: models.StatusNone,
	}
	bs, bsErr := json.Marshal(evStatus)
	require.NoError(s.T(), bsErr)
	req, reqErr := http.NewRequest(http.MethodPut, u.String(), bytes.NewBuffer(bs))
	require.NoError(s.T(), reqErr)
	req.Header.Add(app.IDHeader, s.st.Root.ID.String())
	req.Header.Add(app.AuthorizationHeader, jwt.SignedStringToHeaderValue(s.tok.Token))
	resp, putErr := s.c.Do(req)
	require.NoError(s.T(), putErr)
	require.Equal(s.T(), http.StatusBadRequest, resp.StatusCode)

	// bad owner update
	var empty uuid.UUID
	evOwner := org.UpdateOwnerEvent{
		Owner: models.ID(empty),
	}
	bs, bsErr = json.Marshal(evOwner)
	require.NoError(s.T(), bsErr)
	req, reqErr = http.NewRequest(http.MethodPut, u.String(), bytes.NewBuffer(bs))
	require.NoError(s.T(), reqErr)
	req.Header.Add(app.IDHeader, s.st.Root.ID.String())
	req.Header.Add(app.AuthorizationHeader, jwt.SignedStringToHeaderValue(s.tok.Token))
	resp, putErr = s.c.Do(req)
	require.NoError(s.T(), putErr)
	require.Equal(s.T(), http.StatusBadRequest, resp.StatusCode)
}

func (s *OrgSuite) TestPutNoMatchingEvent() {
	conn, connErr := s.st.Master.Acquire(context.Background())
	require.NoError(s.T(), connErr)
	defer conn.Release()
	// create an org to PUT to
	o, _, _, oErr := app_testing.TestOrgAndUser(conn.Conn(), s.st)
	require.NoError(s.T(), oErr)

	u, urlErr := url.Parse(s.srv.URL + app.APIPath + s.st.APIVersion + "/org/" + o.ID.String())
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
