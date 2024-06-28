package client

import (
	"context"
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

	// try with an unknown user
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

func (s *ClientSuite) TestUpdateUserAPISecretAsRoot() {
	_, updateErr := s.rootClient.UpdateUserAPISecret(s.regularUser.ID)
	require.NoError(s.T(), updateErr)
	// re-read user to get new API secret for regularUserClient
	conn, connErr := s.st.Master.Acquire(context.Background())
	require.NoError(s.T(), connErr)
	defer conn.Release()
	u, readErr := user.Read(context.Background(), conn.Conn(), s.st.VersionKey, s.regularUser.ID)
	require.NoError(s.T(), readErr)
	s.regularUserClient.apiSecret = u.APISecret
	require.NoError(s.T(), s.regularUserClient.newToken())

	// try with an unknown user
	_, updateErr = s.rootClient.UpdateUserAPISecret(models.NewID())
	var rErr ResponseErr
	require.True(s.T(), errors.As(updateErr, &rErr))
	require.Equal(s.T(), http.StatusNotFound, rErr.StatusCode)
}

func (s *ClientSuite) TestUpdateUserAPISecretAsOrgOwner() {
	_, updateErr := s.orgOwnerClient.UpdateUserAPISecret(s.regularUser.ID)
	require.NoError(s.T(), updateErr)
	// re-read user to get new API secret for regularUserClient
	conn, connErr := s.st.Master.Acquire(context.Background())
	require.NoError(s.T(), connErr)
	defer conn.Release()
	u, readErr := user.Read(context.Background(), conn.Conn(), s.st.VersionKey, s.regularUser.ID)
	require.NoError(s.T(), readErr)
	s.regularUserClient.apiSecret = u.APISecret
	require.NoError(s.T(), s.regularUserClient.newToken())

	// try to update api secret of user in another org
	_, updateErr = s.orgOwnerClient.UpdateUserAPISecret(s.st.Root.ID)
	var rErr ResponseErr
	require.True(s.T(), errors.As(updateErr, &rErr))
	require.Equal(s.T(), http.StatusForbidden, rErr.StatusCode)
}

func (s *ClientSuite) TestUpdateUserAPISecretAsRegularUser() {
	_, updateErr := s.regularUserClient.UpdateUserAPISecret(s.regularUser.ID)
	require.NoError(s.T(), updateErr)

	// try to update api secret of user in another org
	_, updateErr = s.regularUserClient.UpdateUserAPISecret(s.st.Root.ID)
	var rErr ResponseErr
	require.True(s.T(), errors.As(updateErr, &rErr))
	require.Equal(s.T(), http.StatusForbidden, rErr.StatusCode)

	// try to update api secret of another user in same org
	_, updateErr = s.regularUserClient.UpdateUserAPISecret(s.orgOwner.ID)
	require.True(s.T(), errors.As(updateErr, &rErr))
	require.Equal(s.T(), http.StatusForbidden, rErr.StatusCode)
}

func (s *ClientSuite) TestUpdateUserDisplayNameAsRoot() {
	_, updateErr := s.rootClient.UpdateUserDisplayName(s.regularUser.ID, safe.TrustedVarChar(security.RandString()))
	require.NoError(s.T(), updateErr)

	// try with an unknown user
	_, updateErr = s.rootClient.UpdateUserDisplayName(models.NewID(), safe.TrustedVarChar(security.RandString()))
	var rErr ResponseErr
	require.True(s.T(), errors.As(updateErr, &rErr))
	require.Equal(s.T(), http.StatusNotFound, rErr.StatusCode)
}

func (s *ClientSuite) TestUpdateUserDisplayNameAsOrgOwner() {
	_, updateErr := s.orgOwnerClient.UpdateUserDisplayName(s.regularUser.ID, safe.TrustedVarChar(security.RandString()))
	require.NoError(s.T(), updateErr)

	// try with a user in another org
	_, updateErr = s.orgOwnerClient.UpdateUserDisplayName(s.st.Root.ID, safe.TrustedVarChar(security.RandString()))
	var rErr ResponseErr
	require.True(s.T(), errors.As(updateErr, &rErr))
	require.Equal(s.T(), http.StatusForbidden, rErr.StatusCode)
}

func (s *ClientSuite) TestUpdateUserDisplayNameAsRegularUser() {
	_, updateErr := s.regularUserClient.UpdateUserDisplayName(s.regularUser.ID, safe.TrustedVarChar(security.RandString()))
	require.NoError(s.T(), updateErr)

	// try to update api secret of user in another org
	_, updateErr = s.regularUserClient.UpdateUserDisplayName(s.st.Root.ID, safe.TrustedVarChar(security.RandString()))
	var rErr ResponseErr
	require.True(s.T(), errors.As(updateErr, &rErr))
	require.Equal(s.T(), http.StatusForbidden, rErr.StatusCode)

	// try to update api secret of another user in same org
	_, updateErr = s.regularUserClient.UpdateUserDisplayName(s.orgOwner.ID, safe.TrustedVarChar(security.RandString()))
	require.True(s.T(), errors.As(updateErr, &rErr))
	require.Equal(s.T(), http.StatusForbidden, rErr.StatusCode)
}

func (s *ClientSuite) TestUpdateUserPasswordAsRoot() {
	_, updateErr := s.rootClient.UpdateUserPassword(s.st.Root.ID, safe.TrustedPassword(security.RandString()))
	require.NoError(s.T(), updateErr)

	// cannot change another user's password, even as root
	_, updateErr = s.rootClient.UpdateUserPassword(s.regularUser.ID, safe.TrustedPassword(security.RandString()))
	var rErr ResponseErr
	require.True(s.T(), errors.As(updateErr, &rErr))
	require.Equal(s.T(), http.StatusForbidden, rErr.StatusCode)

	// try with an unknown user
	_, updateErr = s.rootClient.UpdateUserPassword(models.NewID(), safe.TrustedPassword(security.RandString()))
	require.True(s.T(), errors.As(updateErr, &rErr))
	require.Equal(s.T(), http.StatusNotFound, rErr.StatusCode)
}

func (s *ClientSuite) TestUpdateUserPasswordAsOrgOwner() {
	_, updateErr := s.orgOwnerClient.UpdateUserPassword(s.orgOwner.ID, safe.TrustedPassword(security.RandString()))
	require.NoError(s.T(), updateErr)

	// cannot change another user's password, even as owner of the org
	_, updateErr = s.orgOwnerClient.UpdateUserPassword(s.regularUser.ID, safe.TrustedPassword(security.RandString()))
	var rErr ResponseErr
	require.True(s.T(), errors.As(updateErr, &rErr))
	require.Equal(s.T(), http.StatusForbidden, rErr.StatusCode)

	// try with a user in a different org
	_, updateErr = s.orgOwnerClient.UpdateUserPassword(s.st.Root.ID, safe.TrustedPassword(security.RandString()))
	require.True(s.T(), errors.As(updateErr, &rErr))
	require.Equal(s.T(), http.StatusForbidden, rErr.StatusCode)
}

func (s *ClientSuite) TestUpdateUserPasswordAsRegularUser() {
	_, updateErr := s.regularUserClient.UpdateUserPassword(s.regularUser.ID, safe.TrustedPassword(security.RandString()))
	require.NoError(s.T(), updateErr)

	// try with a user in a different org
	_, updateErr = s.regularUserClient.UpdateUserPassword(s.st.Root.ID, safe.TrustedPassword(security.RandString()))
	var rErr ResponseErr
	require.True(s.T(), errors.As(updateErr, &rErr))
	require.Equal(s.T(), http.StatusForbidden, rErr.StatusCode)

	// try with a different user in same org
	_, updateErr = s.regularUserClient.UpdateUserPassword(s.orgOwner.ID, safe.TrustedPassword(security.RandString()))
	require.True(s.T(), errors.As(updateErr, &rErr))
	require.Equal(s.T(), http.StatusForbidden, rErr.StatusCode)
}

func (s *ClientSuite) TestUpdateUserStatusAsRoot() {
	_, updateErr := s.rootClient.UpdateUserStatus(s.regularUser.ID, models.StatusInactive)
	require.NoError(s.T(), updateErr)
	// change it back
	_, updateErr = s.rootClient.UpdateUserStatus(s.regularUser.ID, models.StatusActive)
	require.NoError(s.T(), updateErr)

	// try with an unknown user
	_, updateErr = s.rootClient.UpdateUserStatus(models.NewID(), models.StatusInactive)
	var rErr ResponseErr
	require.True(s.T(), errors.As(updateErr, &rErr))
	require.Equal(s.T(), http.StatusNotFound, rErr.StatusCode)
}

func (s *ClientSuite) TestUpdateUserStatusAsOrgOwner() {
	_, updateErr := s.orgOwnerClient.UpdateUserStatus(s.regularUser.ID, models.StatusInactive)
	require.NoError(s.T(), updateErr)
	// change it back
	_, updateErr = s.orgOwnerClient.UpdateUserStatus(s.regularUser.ID, models.StatusActive)
	require.NoError(s.T(), updateErr)

	// try with a user in another org
	_, updateErr = s.orgOwnerClient.UpdateUserStatus(s.st.Root.ID, models.StatusInactive)
	var rErr ResponseErr
	require.True(s.T(), errors.As(updateErr, &rErr))
	require.Equal(s.T(), http.StatusForbidden, rErr.StatusCode)
}

func (s *ClientSuite) TestUpdateUserStatusAsRegularUser() {
	_, updateErr := s.regularUserClient.UpdateUserStatus(s.regularUser.ID, models.StatusActive)
	var rErr ResponseErr
	require.True(s.T(), errors.As(updateErr, &rErr))
	require.Equal(s.T(), http.StatusForbidden, rErr.StatusCode)

	// try to update api secret of user in another org
	_, updateErr = s.regularUserClient.UpdateUserStatus(s.st.Root.ID, models.StatusActive)
	require.True(s.T(), errors.As(updateErr, &rErr))
	require.Equal(s.T(), http.StatusForbidden, rErr.StatusCode)

	// try to update api secret of another user in same org
	_, updateErr = s.regularUserClient.UpdateUserStatus(s.orgOwner.ID, models.StatusActive)
	require.True(s.T(), errors.As(updateErr, &rErr))
	require.Equal(s.T(), http.StatusForbidden, rErr.StatusCode)
}
