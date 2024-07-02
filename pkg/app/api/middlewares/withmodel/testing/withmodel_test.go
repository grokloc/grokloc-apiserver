package testing

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/grokloc/grokloc-apiserver/pkg/app"
	"github.com/grokloc/grokloc-apiserver/pkg/app/api/middlewares/request"
	"github.com/grokloc/grokloc-apiserver/pkg/app/api/middlewares/withmodel"
	"github.com/grokloc/grokloc-apiserver/pkg/app/models"
	"github.com/grokloc/grokloc-apiserver/pkg/app/state/unit"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

type WithModelSuite struct {
	suite.Suite
	st  *app.State
	srv *httptest.Server
}

func (s *WithModelSuite) SetupSuite() {
	st, stErr := unit.State()
	require.NoError(s.T(), stErr)
	s.st = st

	rtr := chi.NewRouter()
	rtr.Use(request.Middleware(st))
	rtr.Route("/org", func(rtr chi.Router) {
		rtr.Route("/{id}", func(rtr chi.Router) {
			rtr.Use(withmodel.Middleware(st, models.KindOrg))
			rtr.Get("/", func(w http.ResponseWriter, r *http.Request) {
				_ = withmodel.GetModelWithOrg(r)
			})
		})
	})
	rtr.Route("/user", func(rtr chi.Router) {
		rtr.Route("/{id}", func(rtr chi.Router) {
			rtr.Use(withmodel.Middleware(st, models.KindUser))
			rtr.Get("/", func(w http.ResponseWriter, r *http.Request) {
				_ = withmodel.GetModelWithUser(r)
			})
		})
	})

	// this route uses an unsupported models.Kind
	rtr.Route("/none", func(rtr chi.Router) {
		rtr.Route("/{id}", func(rtr chi.Router) {
			rtr.Use(withmodel.Middleware(st, models.KindNone))
			rtr.Get("/", func(w http.ResponseWriter, r *http.Request) {
				panic("middleware did not short circuit")
			})
		})
	})
	s.srv = httptest.NewServer(rtr)
}

func (s *WithModelSuite) TestPathID() {
	client := http.Client{}

	// malformed - only need to test once for any model kind
	resp, respErr := client.Get(s.srv.URL + "/org/123456")
	require.NoError(s.T(), respErr)
	require.Equal(s.T(), http.StatusBadRequest, resp.StatusCode)

	// ok - id is the org id which will be retrieved
	resp, respErr = client.Get(s.srv.URL + "/org/" + s.st.Org.ID.String())
	require.NoError(s.T(), respErr)
	require.Equal(s.T(), http.StatusOK, resp.StatusCode)

	// not found
	resp, respErr = client.Get(s.srv.URL + "/org/" + models.NewID().String())
	require.NoError(s.T(), respErr)
	require.Equal(s.T(), http.StatusNotFound, resp.StatusCode)

	// ok - id is the user id which will be retrieved
	resp, respErr = client.Get(s.srv.URL + "/user/" + s.st.Root.ID.String())
	require.NoError(s.T(), respErr)
	require.Equal(s.T(), http.StatusOK, resp.StatusCode)

	// not found
	resp, respErr = client.Get(s.srv.URL + "/user/" + models.NewID().String())
	require.NoError(s.T(), respErr)
	require.Equal(s.T(), http.StatusNotFound, resp.StatusCode)

	// try the failing handler
	resp, respErr = client.Get(s.srv.URL + "/none/" + models.NewID().String())
	require.NoError(s.T(), respErr)
	require.Equal(s.T(), http.StatusInternalServerError, resp.StatusCode)
}

func (s *WithModelSuite) TearDownSuite() {
	s.srv.Close()
}

func TestWithModelSuite(t *testing.T) {
	suite.Run(t, new(WithModelSuite))
}
