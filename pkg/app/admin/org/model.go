// Package org contains package methods for org support.
package org

import (
	"github.com/grokloc/grokloc-apiserver/pkg/app/models"
	"github.com/grokloc/grokloc-apiserver/pkg/safe"
)

// Org models a row of the orgs table.
type Org struct {
	models.Base
	Name  safe.VarChar `json:"name"`
	Owner models.ID    `json:"owner"`
}

// GetID implements models.WithID.
func (o *Org) GetID() models.ID {
	return o.ID
}

// GetOrg implements models.WithOrg.
func (o *Org) GetOrg() models.ID {
	return o.GetID()
}

// GetOrg implements models.WithUser.
func (o *Org) GetUser() models.ID {
	return o.Owner
}

const SchemaVersion = 0
