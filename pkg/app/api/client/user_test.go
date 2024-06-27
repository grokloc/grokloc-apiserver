package client

import (
	"errors"
	"net/http"

	"github.com/grokloc/grokloc-apiserver/pkg/app/admin/user"
	"github.com/grokloc/grokloc-apiserver/pkg/app/models"
	"github.com/grokloc/grokloc-apiserver/pkg/safe"
	"github.com/grokloc/grokloc-apiserver/pkg/security"
	"github.com/stretchr/testify/require"
)

func (s *ClientSuite) TestCreateUserAsRoot() {
	ev := user.CreateEvent{
		DisplayName: safe.TrustedVarChar(security.RandString()),
		Email:       safe.TrustedVarChar(security.RandString()),
		Org:         s.org.ID,
		Password:    safe.TrustedPassword(security.RandString()),
	}
	_, createErr := s.rootClient.CreateUser(ev.DisplayName, ev.Email, ev.Org, ev.Password)
	require.NoError(s.T(), createErr)
}

func (s *ClientSuite) TestCreateUserAsOrgOwner() {
	ev := user.CreateEvent{
		DisplayName: safe.TrustedVarChar(security.RandString()),
		Email:       safe.TrustedVarChar(security.RandString()),
		Org:         s.org.ID,
		Password:    safe.TrustedPassword(security.RandString()),
	}
	_, createErr := s.orgOwnerClient.CreateUser(ev.DisplayName, ev.Email, ev.Org, ev.Password)
	require.NoError(s.T(), createErr)

	// try to create a user in a different org
	ev = user.CreateEvent{
		DisplayName: safe.TrustedVarChar(security.RandString()),
		Email:       safe.TrustedVarChar(security.RandString()),
		Org:         s.st.Root.Org,
		Password:    safe.TrustedPassword(security.RandString()),
	}
	_, createErr = s.orgOwnerClient.CreateUser(ev.DisplayName, ev.Email, ev.Org, ev.Password)
	require.Error(s.T(), createErr)
	var rErr ResponseErr
	require.True(s.T(), errors.As(createErr, &rErr))
	require.Equal(s.T(), http.StatusForbidden, rErr.StatusCode)
}

// TestCreateAsRegularUser demonstrates that user auth cannot create a user.
func (s *ClientSuite) TestCreateUserAsRegularUser() {
	ev := user.CreateEvent{
		DisplayName: safe.TrustedVarChar(security.RandString()),
		Email:       safe.TrustedVarChar(security.RandString()),
		Org:         s.org.ID,
		Password:    safe.TrustedPassword(security.RandString()),
	}
	_, createErr := s.regularUserClient.CreateUser(ev.DisplayName, ev.Email, ev.Org, ev.Password)
	require.Error(s.T(), createErr)
	var rErr ResponseErr
	require.True(s.T(), errors.As(createErr, &rErr))
	require.Equal(s.T(), http.StatusForbidden, rErr.StatusCode)
}

func (s *ClientSuite) TestReadUserAsRoot() {
	_, readErr := s.rootClient.ReadUser(s.regularUser.ID)
	require.NoError(s.T(), readErr)
	_, readErr = s.rootClient.ReadOrg(models.NewID())
	var rErr ResponseErr
	require.True(s.T(), errors.As(readErr, &rErr))
	require.Equal(s.T(), http.StatusNotFound, rErr.StatusCode)
}

func (s *ClientSuite) TestReadUserAsOrgOwner() {
	_, readErr := s.orgOwnerClient.ReadUser(s.regularUser.ID)
	require.NoError(s.T(), readErr)

	// try to read a user in another org
	_, readErr = s.orgOwnerClient.ReadUser(s.st.Root.ID)
	var rErr ResponseErr
	require.True(s.T(), errors.As(readErr, &rErr))
	require.Equal(s.T(), http.StatusForbidden, rErr.StatusCode)
}

func (s *ClientSuite) TestReadUserAsRegularUser() {
	// can read self
	_, readErr := s.regularUserClient.ReadUser(s.regularUser.ID)
	require.NoError(s.T(), readErr)

	// try to read a user in another org
	_, readErr = s.regularUserClient.ReadUser(s.st.Root.ID)
	var rErr ResponseErr
	require.True(s.T(), errors.As(readErr, &rErr))
	require.Equal(s.T(), http.StatusForbidden, rErr.StatusCode)

	// try to read a different user in same org
	_, readErr = s.regularUserClient.ReadUser(s.orgOwner.ID)
	require.True(s.T(), errors.As(readErr, &rErr))
	require.Equal(s.T(), http.StatusForbidden, rErr.StatusCode)
}
