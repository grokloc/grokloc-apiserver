package client

import (
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
	_, oErr := s.rootClient.CreateOrg(ev.Name, ev.OwnerDisplayName, ev.OwnerEmail, ev.OwnerPassword, s.st.DefaultRole)
	require.NoError(s.T(), oErr)
}
