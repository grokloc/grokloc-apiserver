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
	rtr.Route("/{id}", func(rtr chi.Router) {
		rtr.Use(withmodel.Middleware(st, models.KindOrg))
		rtr.Get("/", func(w http.ResponseWriter, r *http.Request) {
			_ = withmodel.GetID(r)
		})
	})
	s.srv = httptest.NewServer(rtr)
}

func (s *WithModelSuite) TestPathID() {
	client := http.Client{}

	// ok - id is the org id which will be retrieved
	resp, respErr := client.Get(s.srv.URL + "/" + s.st.Root.Org.String())
	require.NoError(s.T(), respErr)
	require.Equal(s.T(), http.StatusOK, resp.StatusCode)

	// malformed
	resp, respErr = client.Get(s.srv.URL + "/123456")
	require.NoError(s.T(), respErr)
	require.Equal(s.T(), http.StatusBadRequest, resp.StatusCode)
}

func (s *WithModelSuite) TearDownSuite() {
	s.srv.Close()
}

func TestWithModelSuite(t *testing.T) {
	suite.Run(t, new(WithModelSuite))
}
