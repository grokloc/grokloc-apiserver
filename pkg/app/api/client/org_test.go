package client

import (
	"errors"
	"net/http"

	"github.com/grokloc/grokloc-apiserver/pkg/app/admin/org"
	"github.com/grokloc/grokloc-apiserver/pkg/app/models"
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

// TestCreateOrgAsOrgOwner demonstrates that org owner auth cannot create an org.
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

func (s *ClientSuite) TestReadOrgAsRoot() {
	_, readErr := s.rootClient.ReadOrg(s.org.ID)
	require.NoError(s.T(), readErr)

	// try with an unknown org
	_, readErr = s.rootClient.ReadOrg(models.NewID())
	var rErr ResponseErr
	require.True(s.T(), errors.As(readErr, &rErr))
	require.Equal(s.T(), http.StatusNotFound, rErr.StatusCode)
}

func (s *ClientSuite) TestReadOrgAsOrgOwner() {
	_, readErr := s.orgOwnerClient.ReadOrg(s.org.ID)
	require.NoError(s.T(), readErr)
	_, readErr = s.rootClient.ReadOrg(models.NewID())
	var rErr ResponseErr
	require.True(s.T(), errors.As(readErr, &rErr))
	require.Equal(s.T(), http.StatusNotFound, rErr.StatusCode)
}

func (s *ClientSuite) TestReadOrgAsRegularUser() {
	_, readErr := s.regularUserClient.ReadOrg(s.org.ID)
	var rErr ResponseErr
	require.True(s.T(), errors.As(readErr, &rErr))
	require.Equal(s.T(), http.StatusForbidden, rErr.StatusCode)
}

func (s *ClientSuite) TestReadOrgUsersAsRoot() {
	userIDs, readErr := s.rootClient.ReadOrgUsers(s.org.ID)
	require.NoError(s.T(), readErr)
	require.NotEqual(s.T(), 0, len(userIDs))

	// try with an unknown org
	_, readErr = s.rootClient.ReadOrgUsers(models.NewID())
	var rErr ResponseErr
	require.True(s.T(), errors.As(readErr, &rErr))
	require.Equal(s.T(), http.StatusNotFound, rErr.StatusCode)
}

func (s *ClientSuite) TestReadOrgUsersAsOrgOwner() {
	userIDs, readErr := s.orgOwnerClient.ReadOrgUsers(s.org.ID)
	require.NoError(s.T(), readErr)
	require.NotEqual(s.T(), 0, len(userIDs))
	_, readErr = s.rootClient.ReadOrgUsers(models.NewID())
	var rErr ResponseErr
	require.True(s.T(), errors.As(readErr, &rErr))
	require.Equal(s.T(), http.StatusNotFound, rErr.StatusCode)
}

func (s *ClientSuite) TestReadOrgUsersAsRegularUser() {
	_, readErr := s.regularUserClient.ReadOrg(s.org.ID)
	var rErr ResponseErr
	require.True(s.T(), errors.As(readErr, &rErr))
	require.Equal(s.T(), http.StatusForbidden, rErr.StatusCode)
}

func (s *ClientSuite) TestUpdateOrgOwnerAsRoot() {
	// change regularUser to be owner, then undo the change
	_, updateErr := s.rootClient.UpdateOrgOwner(s.org.ID, s.regularUser.ID)
	require.NoError(s.T(), updateErr)
	_, updateErr = s.rootClient.UpdateOrgOwner(s.org.ID, s.orgOwner.ID)
	require.NoError(s.T(), updateErr)

	// try with an unknown org
	_, updateErr = s.rootClient.UpdateOrgOwner(models.NewID(), s.orgOwner.ID)
	var rErr ResponseErr
	require.True(s.T(), errors.As(updateErr, &rErr))
	require.Equal(s.T(), http.StatusNotFound, rErr.StatusCode)
}

func (s *ClientSuite) TestUpdateOrgOwnerAsOrgOwner() {
	_, updateErr := s.orgOwnerClient.UpdateOrgOwner(s.org.ID, s.regularUser.ID)
	var rErr ResponseErr
	require.True(s.T(), errors.As(updateErr, &rErr))
	require.Equal(s.T(), http.StatusForbidden, rErr.StatusCode)
}

func (s *ClientSuite) TestUpdateOrgOwnerAsRegularUser() {
	_, updateErr := s.regularUserClient.UpdateOrgOwner(s.org.ID, s.regularUser.ID)
	var rErr ResponseErr
	require.True(s.T(), errors.As(updateErr, &rErr))
	require.Equal(s.T(), http.StatusForbidden, rErr.StatusCode)
}

func (s *ClientSuite) TestUpdateOrgStatusAsRoot() {
	// change status to inactive, then undo the change
	_, updateErr := s.rootClient.UpdateOrgStatus(s.org.ID, models.StatusInactive)
	require.NoError(s.T(), updateErr)
	_, updateErr = s.rootClient.UpdateOrgStatus(s.org.ID, models.StatusActive)
	require.NoError(s.T(), updateErr)

	// try with an unknown org
	_, updateErr = s.rootClient.UpdateOrgStatus(models.NewID(), models.StatusActive)
	var rErr ResponseErr
	require.True(s.T(), errors.As(updateErr, &rErr))
	require.Equal(s.T(), http.StatusNotFound, rErr.StatusCode)
}

func (s *ClientSuite) TestUpdateOrgStatusAsOrgOwner() {
	_, updateErr := s.orgOwnerClient.UpdateOrgStatus(s.org.ID, models.StatusInactive)
	var rErr ResponseErr
	require.True(s.T(), errors.As(updateErr, &rErr))
	require.Equal(s.T(), http.StatusForbidden, rErr.StatusCode)
}

func (s *ClientSuite) TestUpdateOrgStatusAsRegularUser() {
	_, updateErr := s.regularUserClient.UpdateOrgStatus(s.org.ID, models.StatusInactive)
	var rErr ResponseErr
	require.True(s.T(), errors.As(updateErr, &rErr))
	require.Equal(s.T(), http.StatusForbidden, rErr.StatusCode)
}

func (s *ClientSuite) TestDeleteOrgAsRoot() {
	// change status to inactive, then undo the change
	updateErr := s.rootClient.DeleteOrg(s.org.ID)
	require.NoError(s.T(), updateErr)
	_, updateErr = s.rootClient.UpdateOrgStatus(s.org.ID, models.StatusActive)
	require.NoError(s.T(), updateErr)
}

func (s *ClientSuite) TestDeleteOrgAsOrgOwner() {
	updateErr := s.orgOwnerClient.DeleteOrg(s.org.ID)
	var rErr ResponseErr
	require.True(s.T(), errors.As(updateErr, &rErr))
	require.Equal(s.T(), http.StatusForbidden, rErr.StatusCode)
}

func (s *ClientSuite) TestDeleteOrgAsRegularUser() {
	updateErr := s.regularUserClient.DeleteOrg(s.org.ID)
	var rErr ResponseErr
	require.True(s.T(), errors.As(updateErr, &rErr))
	require.Equal(s.T(), http.StatusForbidden, rErr.StatusCode)
}
