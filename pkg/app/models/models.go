// Package models provides shared model definitions.
package models

import (
	"context"
	"database/sql/driver"
	"errors"
	"fmt"
	"strconv"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// WithID indicates a model has a retrievable model ID.
type WithID interface {
	GetID() ID
}

// WithOrg indicates a model has a retrievable Org ID.
type WithOrg interface {
	GetOrg() ID
}

// WithUser indicates a model has a retrievable User ID.
type WithUser interface {
	GetUser() ID
}

// Kind is a symbol for a model kind.
type Kind int64

const (
	KindNone = Kind(0)
	KindOrg  = Kind(1)
	KindUser = Kind(2)
)

// Role describes the context of a model row.
// Role is an int64 when stored in the db.
type Role int64

// Status describes the active state of a model row.
// Status is an int64 when stored in the db.
type Status int64

const (
	RoleNone          = Role(0) // never store
	RoleNormal        = Role(1)
	RoleAdmin         = Role(2)
	RoleTest          = Role(3)
	StatusNone        = Status(0) // never store
	StatusUnconfirmed = Status(1)
	StatusActive      = Status(2)
	StatusInactive    = Status(3)
)

// NewRole creates a Role from an int.
func NewRole(role int64) (Role, error) {
	switch role {
	case 1:
		// default
		return RoleNormal, nil
	case 2:
		return RoleAdmin, nil
	case 3:
		return RoleTest, nil
	default:
		return RoleNone, ErrRole
	}
}

func (r *Role) UnmarshalJSON(bs []byte) error {
	asInt, err := strconv.ParseInt(string(bs), 10, 64)
	if err != nil {
		return err
	}
	asRole, err := NewRole(asInt)
	if err != nil {
		return err
	}
	*r = asRole
	return nil
}

func (r *Role) Scan(src interface{}) error {
	switch src := src.(type) {
	case nil:
		return nil

	case int64:
		r_, err := NewRole(src)
		if err != nil {
			return err
		}
		*r = r_

	default:
		return fmt.Errorf("scan %v into Role", src)
	}

	return nil
}

func (r Role) Value() (driver.Value, error) {
	return int64(r), nil
}

func (r Role) IsEmpty() bool {
	return r == RoleNone
}

// NewStatus creates a Status from an int.
func NewStatus(status int64) (Status, error) {
	switch status {
	case 1:
		// default
		return StatusUnconfirmed, nil
	case 2:
		return StatusActive, nil
	case 3:
		return StatusInactive, nil
	default:
		return StatusNone, ErrStatus
	}
}

func (s *Status) UnmarshalJSON(bs []byte) error {
	asInt, err := strconv.ParseInt(string(bs), 10, 64)
	if err != nil {
		return err
	}
	asStatus, err := NewStatus(asInt)
	if err != nil {
		return err
	}
	*s = asStatus
	return nil
}

func (s *Status) Scan(src interface{}) error {
	switch src := src.(type) {
	case nil:
		return nil

	case int64:
		s_, err := NewStatus(src)
		if err != nil {
			return err
		}
		*s = s_

	default:
		return fmt.Errorf("scan %v into Status", src)
	}

	return nil
}

func (s Status) Value() (driver.Value, error) {
	return int64(s), nil
}

func (s Status) IsEmpty() bool {
	return s == StatusNone
}

// Meta models metadata common to all models.
//
// Ctime and Mtime are set in db by a trigger as unixtime.
// Signature is set in db by a trigger as a UUID -> Text conversion.
//
// Default initialization will have Role as RoleNormal.
// Status as StatusUnconfirmed, which is intended.
type Meta struct {
	Ctime         int64     `json:"ctime"`
	Mtime         int64     `json:"mtime"`
	Role          Role      `json:"role"`
	SchemaVersion int64     `json:"schema_version"`
	Signature     uuid.UUID `json:"signature"`
	Status        Status    `json:"status"`
}

// ID is implemented as a UUID.
type ID uuid.UUID

func NewID() ID {
	return ID(uuid.New())
}

func (id ID) String() string {
	return uuid.UUID(id).String()
}

func (id ID) MarshalJSON() ([]byte, error) {
	return []byte(fmt.Sprintf(`"%s"`, uuid.UUID(id).String())), nil
}

func (id *ID) UnmarshalJSON(bs []byte) error {
	u, err := uuid.Parse(string(bs))
	if err != nil {
		return err
	}

	// for the purposes of an ID, an all-zero ID is likely an unmarshal error
	var empty uuid.UUID
	if u == empty {
		return errors.New("unmarshal to empty/all-zero uuid")
	}

	*id = ID(u)
	return nil
}

func (id *ID) Scan(src interface{}) error {
	u := &uuid.UUID{}
	err := u.Scan(src)
	if err != nil {
		return err
	}
	*id = ID(*u)
	return nil
}

func (id ID) Value() (driver.Value, error) {
	return id.String(), nil
}

func (id ID) IsEmpty() bool {
	var empty uuid.UUID
	return id == ID(empty)
}

// Base models core attributes common to all models.
type Base struct {
	ID   ID   `json:"id"`
	Meta Meta `json:"meta"`
}

// Update changes the value of a column given a tablename, column name and id.
//
// Caller should Refresh() their model row again to get refreshed signature,
// ctime, mtime etc.
func Update(ctx context.Context,
	conn *pgx.Conn,
	tableName string,
	id ID,
	colName string,
	val any,
) error {
	q := fmt.Sprintf(`update %s set %s = $1 where id = $2`, tableName, colName)

	result, err := conn.Exec(ctx, q, val, id.String())
	if err != nil {
		return err
	}

	updated := result.RowsAffected()
	if updated == 0 {
		return pgx.ErrNoRows
	}
	if updated != 1 {
		return ErrRowsAffected
	}

	return nil
}
