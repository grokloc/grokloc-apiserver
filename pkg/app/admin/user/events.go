package user

import (
	"encoding/json"
	"errors"

	"github.com/grokloc/grokloc-apiserver/pkg/app/models"
	"github.com/grokloc/grokloc-apiserver/pkg/safe"
	"github.com/grokloc/grokloc-apiserver/pkg/security"
	"github.com/matthewhartstonge/argon2"
)

type CreateEvent struct {
	DisplayName  safe.VarChar   `json:"display_name"`
	Email        safe.VarChar   `json:"email"`
	Org          models.ID      `json:"org"`
	Password     safe.Password  `json:"password"`
	argon2Config *argon2.Config `json:"-"`
}

func NewCreateEvent(argon2Config *argon2.Config) (*CreateEvent, error) {
	if argon2Config == nil {
		return nil, errors.New("missing argon2 config")
	}
	return &CreateEvent{argon2Config: argon2Config}, nil
}

func (ev CreateEvent) isEmpty() bool {
	return ev.DisplayName.IsEmpty() ||
		ev.Email.IsEmpty() ||
		ev.Org.IsEmpty() ||
		ev.Password.IsEmpty()
}

// UnmarshalJSON assumes Password is cleartext and hashes it with argon2.
// This minimizes the window to access the cleartext password accidentally.
func (ev *CreateEvent) UnmarshalJSON(bs []byte) error {
	if ev.argon2Config == nil {
		panic("missing argon2 config")
	}
	type inner CreateEvent
	var t inner
	umErr := json.Unmarshal(bs, &t)
	if umErr != nil {
		return umErr
	}

	derivedPassword, deriveErr := security.DerivePassword(t.Password.String(), *ev.argon2Config)
	if deriveErr != nil {
		return deriveErr
	}
	t.Password = *derivedPassword
	*ev = CreateEvent(t)
	if ev.isEmpty() {
		return errors.New("CreateEvent has empty required fields")
	}
	// ev will now have a nil argon2Config, its not needed anymore
	return nil
}

type UpdateAPISecretEvent struct {
	GenerateAPISecret bool `json:"generate_api_secret"`
}

type UpdateDisplayNameEvent struct {
	DisplayName safe.VarChar `json:"display_name"`
}

type UpdatePasswordEvent struct {
	Password safe.Password `json:"password"`
}

type UpdateStatusEvent struct {
	Status models.Status `json:"status"`
}
