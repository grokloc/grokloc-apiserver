package testing

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/grokloc/grokloc-apiserver/pkg/app"

	"github.com/grokloc/grokloc-apiserver/pkg/app/api"
	"github.com/grokloc/grokloc-apiserver/pkg/app/api/handlers/token"
	"github.com/grokloc/grokloc-apiserver/pkg/app/jwt"
	"github.com/grokloc/grokloc-apiserver/pkg/app/state/unit"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

type OrgSuite struct {
	suite.Suite
	c   http.Client
	srv *httptest.Server
	st  *app.State
	tok token.JSONToken
}

func (s *OrgSuite) SetupSuite() {
	st, stErr := unit.State()
	require.NoError(s.T(), stErr)
	rtr := api.NewRouter(st)
	s.srv = httptest.NewServer(rtr)
	s.st = st

	// get root token
	u, urlErr := url.Parse(s.srv.URL + "/token")
	require.NoError(s.T(), urlErr)
	tokenRequest := jwt.EncodeTokenRequest(s.st.Root.ID, s.st.Root.APISecret.String())
	req0 := http.Request{
		URL:    u,
		Method: http.MethodPost,
		Header: map[string][]string{
			app.IDHeader:           {s.st.Root.ID.String()},
			app.TokenRequestHeader: {tokenRequest},
		},
	}
	s.c = http.Client{}
	resp, postErr := s.c.Do(&req0)
	require.NoError(s.T(), postErr)
	defer resp.Body.Close()
	body, readErr := io.ReadAll(resp.Body)
	require.NoError(s.T(), readErr)
	umErr := json.Unmarshal(body, &s.tok)
	require.NoError(s.T(), umErr)
	require.NotEmpty(s.T(), s.tok.Token)
}

func (s *OrgSuite) TearDownSuite() {
	s.srv.Close()
}

func TestOrgSuite(t *testing.T) {
	suite.Run(t, new(OrgSuite))
}
