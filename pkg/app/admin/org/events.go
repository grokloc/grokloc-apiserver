package org

import (
	"bytes"
	"encoding/json"
	"errors"

	"github.com/grokloc/grokloc-apiserver/pkg/app/models"
	"github.com/grokloc/grokloc-apiserver/pkg/safe"
	"github.com/grokloc/grokloc-apiserver/pkg/security"
	"github.com/matthewhartstonge/argon2"
)

type CreateEvent struct {
	Name             safe.VarChar  `json:"name"`
	OwnerDisplayName safe.VarChar  `json:"owner_display_name"`
	OwnerEmail       safe.VarChar  `json:"owner_email"`
	OwnerPassword    safe.Password `json:"owner_password"`
	Role             models.Role   `json:"role"`
	// argon2Config is modified internally, not for use by external callers
	argon2Config *argon2.Config `json:"-"`
}

func NewCreateEvent(argon2Config *argon2.Config) (*CreateEvent, error) {
	if argon2Config == nil {
		return nil, errors.New("missing argon2 config")
	}
	return &CreateEvent{argon2Config: argon2Config}, nil
}

func (ev CreateEvent) isEmpty() bool {
	return ev.Name.IsEmpty() ||
		ev.OwnerDisplayName.IsEmpty() ||
		ev.OwnerEmail.IsEmpty() ||
		ev.OwnerPassword.IsEmpty() ||
		ev.Role.IsEmpty()
}

// UnmarshalJSON assumes OwnerPassword is cleartext and hashes it with argon2.
// This minimizes the window to access the cleartext password accidentally.
func (ev *CreateEvent) UnmarshalJSON(bs []byte) error {
	if ev.argon2Config == nil {
		panic("missing argon2 config")
	}
	type inner CreateEvent
	var t inner
	decoder := json.NewDecoder(bytes.NewReader(bs))
	decoder.DisallowUnknownFields()
	dcErr := decoder.Decode(&t)
	if dcErr != nil {
		return dcErr
	}

	derivedPassword, deriveErr := security.DerivePassword(t.OwnerPassword.String(), *ev.argon2Config)
	if deriveErr != nil {
		return deriveErr
	}
	t.OwnerPassword = *derivedPassword
	*ev = CreateEvent(t)
	if ev.isEmpty() {
		return errors.New("CreateEvent has empty required fields")
	}
	// ev will now have a nil argon2Config, its not needed anymore
	return nil
}

type UpdateOwnerEvent struct {
	Owner models.ID `json:"owner"`
}

type UpdateStatusEvent struct {
	Status models.Status `json:"status"`
}
