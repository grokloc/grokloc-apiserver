// Package user contains package methods for user support.
package user

import (
	"github.com/google/uuid"
	"github.com/grokloc/grokloc-apiserver/pkg/app/models"
	"github.com/grokloc/grokloc-apiserver/pkg/safe"
)

// User models a row of the users table.
type User struct {
	models.Base
	// APISecret may be in both encrypted and decrypted states
	// so it is set as safe.VarChar, although it will be forged
	// from a models.ID instance.
	APISecret         safe.VarChar  `json:"api_secret"`
	APISecretDigest   string        `json:"api_secret_digest"`
	DisplayName       safe.VarChar  `json:"display_name"`
	DisplayNameDigest string        `json:"display_name_digest"`
	Email             safe.VarChar  `json:"email"`
	EmailDigest       string        `json:"email_digest"`
	Org               models.ID     `json:"org"`
	Password          safe.Password `json:"-"` // assumed derived
	KeyVersion        uuid.UUID     `json:"-"`
	encrypted         bool          `json:"-"` // internal state
}

// GetID implements models.WithID.
func (u *User) GetID() models.ID {
	return u.ID
}

// GetOrg implements models.WithOrg.
func (u *User) GetOrg() models.ID {
	return u.Org
}

// GetUser implements models.WithUser.
func (u *User) GetUser() models.ID {
	return u.GetID()
}

const SchemaVersion = 0
