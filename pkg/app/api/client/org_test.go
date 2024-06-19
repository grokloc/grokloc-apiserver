package client

import (
	"errors"
	"net/http"

	"github.com/grokloc/grokloc-apiserver/pkg/app/admin/org"
	"github.com/grokloc/grokloc-apiserver/pkg/safe"
	"github.com/grokloc/grokloc-apiserver/pkg/security"
	"github.com/stretchr/testify/require"
)

func (s *ClientSuite) TestCreateOrgAsRoot() {
	ev := org.CreateEvent{
		Name:             safe.TrustedVarChar(security.RandString()),
		OwnerDisplayName: safe.TrustedVarChar(security.RandString()),
		OwnerEmail:       safe.TrustedVarChar(security.RandString()),
		OwnerPassword:    safe.TrustedPassword(security.RandString()),
		Role:             s.st.DefaultRole,
	}
	_, createErr := s.rootClient.CreateOrg(ev.Name, ev.OwnerDisplayName, ev.OwnerEmail, ev.OwnerPassword, ev.Role)
	require.NoError(s.T(), createErr)
}

func (s *ClientSuite) TestCreateOrgAsOrgOwner() {
	ev := org.CreateEvent{
		Name:             safe.TrustedVarChar(security.RandString()),
		OwnerDisplayName: safe.TrustedVarChar(security.RandString()),
		OwnerEmail:       safe.TrustedVarChar(security.RandString()),
		OwnerPassword:    safe.TrustedPassword(security.RandString()),
		Role:             s.st.DefaultRole,
	}
	_, createErr := s.orgOwnerClient.CreateOrg(ev.Name, ev.OwnerDisplayName, ev.OwnerEmail, ev.OwnerPassword, ev.Role)
	require.Error(s.T(), createErr)
	var rErr ResponseErr
	require.True(s.T(), errors.As(createErr, &rErr))
	require.Equal(s.T(), http.StatusForbidden, rErr.StatusCode)
}

func (s *ClientSuite) TestCreateOrgAsRegularUser() {
	ev := org.CreateEvent{
		Name:             safe.TrustedVarChar(security.RandString()),
		OwnerDisplayName: safe.TrustedVarChar(security.RandString()),
		OwnerEmail:       safe.TrustedVarChar(security.RandString()),
		OwnerPassword:    safe.TrustedPassword(security.RandString()),
		Role:             s.st.DefaultRole,
	}
	_, createErr := s.regularUserClient.CreateOrg(ev.Name, ev.OwnerDisplayName, ev.OwnerEmail, ev.OwnerPassword, ev.Role)
	require.Error(s.T(), createErr)
	var rErr ResponseErr
	require.True(s.T(), errors.As(createErr, &rErr))
	require.Equal(s.T(), http.StatusForbidden, rErr.StatusCode)
}
