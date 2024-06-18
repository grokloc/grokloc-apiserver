package testing

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/grokloc/grokloc-apiserver/pkg/app"
	"github.com/grokloc/grokloc-apiserver/pkg/app/admin/org"
	"github.com/grokloc/grokloc-apiserver/pkg/app/admin/user"
	"github.com/grokloc/grokloc-apiserver/pkg/app/api/middlewares/auth/withuser"
	"github.com/grokloc/grokloc-apiserver/pkg/app/api/middlewares/request"
	"github.com/grokloc/grokloc-apiserver/pkg/app/models"
	"github.com/grokloc/grokloc-apiserver/pkg/app/state/unit"
	app_testing "github.com/grokloc/grokloc-apiserver/pkg/app/testing"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

type WithUserSuite struct {
	suite.Suite
	st          *app.State
	srv         *httptest.Server
	org         *org.Org
	owner       *user.User
	regularUser *user.User
}

func (s *WithUserSuite) SetupSuite() {
	st, stErr := unit.State()
	require.NoError(s.T(), stErr)
	s.st = st
	conn, connErr := s.st.Master.Acquire(context.Background())
	require.NoError(s.T(), connErr)
	defer conn.Release()

	var createErr error
	s.org, s.owner, s.regularUser, createErr = app_testing.TestOrgAndUser(conn.Conn(), s.st)
	require.NoError(s.T(), createErr)

	rtr := chi.NewRouter()
	rtr.Use(request.Middleware(st))
	rtr.Use(withuser.Middleware(st))
	rtr.Get("/", func(w http.ResponseWriter, r *http.Request) {})

	s.srv = httptest.NewServer(rtr)
}

func (s *WithUserSuite) TestWithRegularUser() {
	u, urlErr := url.Parse(s.srv.URL + "/")
	require.NoError(s.T(), urlErr)
	req := http.Request{
		URL:    u,
		Method: http.MethodGet,
		Header: map[string][]string{
			app.IDHeader: {s.regularUser.ID.String()},
		},
	}
	client := http.Client{}
	resp, getErr := client.Do(&req)
	require.NoError(s.T(), getErr)
	require.Equal(s.T(), http.StatusOK, resp.StatusCode)
}

func (s *WithUserSuite) TestWithUserOrgOwner() {
	u, urlErr := url.Parse(s.srv.URL + "/")
	require.NoError(s.T(), urlErr)
	req := http.Request{
		URL:    u,
		Method: http.MethodGet,
		Header: map[string][]string{
			app.IDHeader: {s.owner.ID.String()},
		},
	}
	client := http.Client{}
	resp, getErr := client.Do(&req)
	require.NoError(s.T(), getErr)
	require.Equal(s.T(), http.StatusOK, resp.StatusCode)
}

func (s *WithUserSuite) TestWithUserRootUser() {
	u, urlErr := url.Parse(s.srv.URL + "/")
	require.NoError(s.T(), urlErr)
	req := http.Request{
		URL:    u,
		Method: http.MethodGet,
		Header: map[string][]string{
			app.IDHeader: {s.st.Root.ID.String()},
		},
	}
	client := http.Client{}
	resp, getErr := client.Do(&req)
	require.NoError(s.T(), getErr)
	require.Equal(s.T(), http.StatusOK, resp.StatusCode)
}

func (s *WithUserSuite) TestWithUserMissingUser() {
	u, urlErr := url.Parse(s.srv.URL + "/")
	require.NoError(s.T(), urlErr)
	req := http.Request{
		URL:    u,
		Method: http.MethodGet,
		Header: map[string][]string{
			app.IDHeader: {models.NewID().String()},
		},
	}
	client := http.Client{}
	resp, getErr := client.Do(&req)
	require.NoError(s.T(), getErr)
	require.Equal(s.T(), http.StatusNotFound, resp.StatusCode)
}

func (s *WithUserSuite) TestWithUserInactiveUser() {
	conn, connErr := s.st.Master.Acquire(context.Background())
	require.NoError(s.T(), connErr)
	_, owner, _, createErr := app_testing.TestOrgAndUser(conn.Conn(), s.st)
	require.NoError(s.T(), createErr)
	updateErr := owner.UpdateStatus(context.Background(), conn.Conn(), s.st.VersionKey, models.StatusInactive)
	require.NoError(s.T(), updateErr)

	u, urlErr := url.Parse(s.srv.URL + "/")
	require.NoError(s.T(), urlErr)
	req := http.Request{
		URL:    u,
		Method: http.MethodGet,
		Header: map[string][]string{
			app.IDHeader: {owner.ID.String()},
		},
	}
	client := http.Client{}
	resp, getErr := client.Do(&req)
	require.NoError(s.T(), getErr)
	require.Equal(s.T(), http.StatusBadRequest, resp.StatusCode)
}

func (s *WithUserSuite) TestWithUserInactiveOrg() {
	conn, connErr := s.st.Master.Acquire(context.Background())
	require.NoError(s.T(), connErr)
	org, owner, _, createErr := app_testing.TestOrgAndUser(conn.Conn(), s.st)
	require.NoError(s.T(), createErr)
	updateErr := org.UpdateStatus(context.Background(), conn.Conn(), models.StatusInactive)
	require.NoError(s.T(), updateErr)

	u, urlErr := url.Parse(s.srv.URL + "/")
	require.NoError(s.T(), urlErr)
	req := http.Request{
		URL:    u,
		Method: http.MethodGet,
		Header: map[string][]string{
			app.IDHeader: {owner.ID.String()},
		},
	}
	client := http.Client{}
	resp, getErr := client.Do(&req)
	require.NoError(s.T(), getErr)
	require.Equal(s.T(), http.StatusBadRequest, resp.StatusCode)
}

func (s *WithUserSuite) TearDownSuite() {
	s.srv.Close()
}

func TestWithUserSuite(t *testing.T) {
	suite.Run(t, new(WithUserSuite))
}
