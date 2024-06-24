package testing

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/grokloc/grokloc-apiserver/pkg/app"
	"github.com/grokloc/grokloc-apiserver/pkg/app/admin/org"
	"github.com/grokloc/grokloc-apiserver/pkg/app/admin/user"
	"github.com/grokloc/grokloc-apiserver/pkg/app/api/middlewares/auth/withauth"
	"github.com/grokloc/grokloc-apiserver/pkg/app/api/middlewares/auth/withuser"
	"github.com/grokloc/grokloc-apiserver/pkg/app/api/middlewares/request"
	"github.com/grokloc/grokloc-apiserver/pkg/app/api/middlewares/withmodel"
	"github.com/grokloc/grokloc-apiserver/pkg/app/models"
	"github.com/grokloc/grokloc-apiserver/pkg/app/state/unit"
	app_testing "github.com/grokloc/grokloc-apiserver/pkg/app/testing"
	"github.com/grokloc/grokloc-apiserver/pkg/safe"
	"github.com/grokloc/grokloc-apiserver/pkg/security"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

type WithAuthSuite struct {
	suite.Suite
	st                               *app.State
	srv                              *httptest.Server
	org, otherOrg                    *org.Org
	owner, otherOrgOwner             *user.User
	regularUser, otherOrgRegularUser *user.User
	teammateRegularUser              *user.User
}

func (s *WithAuthSuite) SetupSuite() {
	st, stErr := unit.State()
	require.NoError(s.T(), stErr)
	s.st = st
	conn, connErr := s.st.Master.Acquire(context.Background())
	require.NoError(s.T(), connErr)
	defer conn.Release()

	var createErr error
	s.org, s.owner, s.regularUser, createErr = app_testing.TestOrgAndUser(conn.Conn(), s.st)
	require.NoError(s.T(), createErr)
	s.otherOrg, s.otherOrgOwner, s.otherOrgRegularUser, createErr = app_testing.TestOrgAndUser(conn.Conn(), s.st)
	require.NoError(s.T(), createErr)

	// additional user in org, a teammate
	password, passwordErr := security.DerivePassword(security.RandString(), s.st.Argon2Config)
	require.NoError(s.T(), passwordErr)
	s.teammateRegularUser, createErr = user.Create(
		context.Background(),
		conn.Conn(),
		safe.TrustedVarChar(security.RandString()),
		safe.TrustedVarChar(security.RandString()),
		s.org.ID,
		*password,
		s.st.VersionKey,
	)
	require.NoError(s.T(), createErr)

	rtr := chi.NewRouter()
	rtr.Use(request.Middleware(st))
	rtr.Use(withuser.Middleware(st))

	rtr.With(withauth.RequireOneOf(withuser.AuthRoot)).
		Get("/root", func(w http.ResponseWriter, r *http.Request) {})

	rtr.Route("/org", func(rtr chi.Router) {
		rtr.Route("/{id}", func(rtr chi.Router) {
			rtr.Use(withmodel.Middleware(st, models.KindOrg))
			rtr.Use(withauth.RequireOneOf(withuser.AuthOrg))
			rtr.Get("/", func(w http.ResponseWriter, r *http.Request) {
				_ = withmodel.GetModelWithID(r)
				_ = withmodel.GetModelWithOrg(r)
			})
		})
	})

	rtr.Route("/user", func(rtr chi.Router) {
		rtr.Route("/{id}", func(rtr chi.Router) {
			rtr.Use(withmodel.Middleware(st, models.KindUser))
			rtr.Use(withauth.RequireOneOf(withuser.AuthUser))
			rtr.Get("/", func(w http.ResponseWriter, r *http.Request) {
				_ = withmodel.GetModelWithID(r)
			})
		})
	})

	rtr.Route("/team", func(rtr chi.Router) {
		rtr.Route("/{id}", func(rtr chi.Router) {
			rtr.Use(withmodel.Middleware(st, models.KindOrg))
			rtr.Use(withauth.RequireOneOf(withuser.AuthTeammate))
			rtr.Get("/", func(w http.ResponseWriter, r *http.Request) {
				_ = withmodel.GetModelWithID(r)
			})
		})
	})

	s.srv = httptest.NewServer(rtr)
}

func (s *WithAuthSuite) TestTrue() {
	require.True(s.T(), true)
}

func (s *WithAuthSuite) TearDownSuite() {
	s.srv.Close()
}

func TestWithAuthSuite(t *testing.T) {
	suite.Run(t, new(WithAuthSuite))
}
