package org

import (
	"context"

	"github.com/grokloc/grokloc-apiserver/pkg/app/admin/user"
	"github.com/grokloc/grokloc-apiserver/pkg/app/audit"
	"github.com/grokloc/grokloc-apiserver/pkg/app/models"
	"github.com/grokloc/grokloc-apiserver/pkg/safe"
	"github.com/grokloc/grokloc-apiserver/pkg/security"
	"github.com/jackc/pgx/v5"
)

// Insert an Org into the db.
func (o *Org) Insert(ctx context.Context, conn *pgx.Conn) error {
	const insertQuery = `
      	insert into orgs
        	(id,
         	name,
         	owner,
         	role,
         	schema_version,
         	status)
      	values
      	($1,$2,$3,$4,$5,$6)
      	`

	result, err := conn.Exec(ctx, insertQuery,
		o.ID.String(),
		o.Name.String(),
		o.Owner.String(),
		o.Meta.Role,
		o.Meta.SchemaVersion,
		o.Meta.Status,
	)
	if err != nil {
		if models.UniqueConstraint(err) {
			return models.ErrConflict
		}
		return err
	}

	inserted := result.RowsAffected()
	if inserted != 1 {
		return models.ErrRowsAffected
	}

	return nil
}

// Create inserts a new org and org owner into the db.
func Create(
	ctx context.Context,
	conn *pgx.Conn,
	name safe.VarChar,
	ownerDisplayName safe.VarChar,
	ownerEmail safe.VarChar,
	ownerPassword safe.Password,
	role models.Role,
	versionKey *security.VersionKey,
) (*Org, *user.User, error) {
	keyVersion, key, keyErr := versionKey.GetCurrent()
	if keyErr != nil {
		return nil, nil, keyErr
	}

	o := &Org{Name: name}
	o.ID = models.NewID()
	o.Meta.Role = role
	o.Meta.Status = models.StatusActive
	o.Meta.SchemaVersion = SchemaVersion

	owner, ownerErr := user.New(ownerDisplayName, ownerEmail, o.ID, ownerPassword)
	if ownerErr != nil {
		return nil, nil, ownerErr
	}
	owner.Meta.Status = models.StatusActive
	owner.Meta.Role = role // owner inherits org role

	o.Owner = owner.ID // link back to owner

	tx, txErr := conn.Begin(ctx)
	if txErr != nil {
		return nil, nil, txErr
	}
	defer tx.Rollback(ctx) // nolint:errcheck

	ownerInsertErr := owner.Insert(ctx, tx.Conn(), keyVersion, key)
	if ownerInsertErr != nil {
		return nil, nil, ownerInsertErr
	}

	orgInsertErr := o.Insert(ctx, tx.Conn())
	if orgInsertErr != nil {
		return nil, nil, orgInsertErr
	}

	// re-read both org and owner from db to get populated metadata
	oRead, oReadErr := Read(ctx, tx.Conn(), o.ID)
	if oReadErr != nil {
		return nil, nil, oReadErr
	}

	ownerRead, ownerReadErr := user.Read(ctx, tx.Conn(), versionKey, owner.ID)
	if ownerReadErr != nil {
		return nil, nil, ownerReadErr
	}

	commitErr := tx.Commit(ctx)
	if commitErr != nil {
		return nil, nil, commitErr
	}

	return oRead, ownerRead, nil
}

// Read initializes a User from an existing row.
func Read(
	ctx context.Context,
	conn *pgx.Conn,
	id models.ID,
) (*Org, error) {
	var o Org

	const selectQuery = `
      	select
        	name,
        	owner,
        	ctime,
        	mtime,
        	role,
        	schema_version,
        	signature,
        	status
      	from orgs
      	where id = $1
      	`

	selectErr := conn.QueryRow(ctx, selectQuery, id.String()).
		Scan(&o.Name,
			&o.Owner,
			&o.Meta.Ctime,
			&o.Meta.Mtime,
			&o.Meta.Role,
			&o.Meta.SchemaVersion,
			&o.Meta.Signature,
			&o.Meta.Status,
		)
	if selectErr != nil {
		if pgx.ErrNoRows == selectErr {
			return nil, models.ErrNotFound
		}
		return nil, selectErr
	}

	// mismatch schema versions require migration
	if SchemaVersion != o.Meta.SchemaVersion {
		migrated := false
		// put migration code here

		if !migrated {
			return nil, models.ErrModelMigrate
		}
	}

	o.ID = id

	return &o, nil
}

// Users returns the list of user ids in the org.
func Users(
	ctx context.Context,
	conn *pgx.Conn,
	id models.ID,
) ([]models.ID, error) {
	// want to return ErrNotFound if org does not exist
	_, readErr := Read(ctx, conn, id)
	if readErr != nil {
		return nil, readErr
	}
	const selectQuery = `select id from users where org = $1`
	rows, queryErr := conn.Query(ctx, selectQuery, id)
	if queryErr != nil {
		return nil, queryErr
	}
	ids, collectErr := pgx.CollectRows(rows, pgx.RowTo[models.ID])
	if collectErr != nil {
		return nil, collectErr
	}
	return ids, nil
}

// Refresh will re-initialize data fields after an update, typically
// inside the same txn that performed the update.
func (o *Org) Refresh(ctx context.Context, conn *pgx.Conn) error {
	oRead, oReadErr := Read(ctx, conn, o.ID)
	if oReadErr != nil {
		return oReadErr
	}

	o.Name = oRead.Name
	o.Owner = oRead.Owner
	o.Meta = oRead.Meta

	return nil
}

// UpdateOwner assigns a new user in the org as the owner.
func (o *Org) UpdateOwner(ctx context.Context,
	conn *pgx.Conn,
	newOwner models.ID,
) error {
	tx, txErr := conn.Begin(ctx)
	if txErr != nil {
		return txErr
	}
	defer tx.Rollback(ctx) // nolint:errcheck

	const updateOwnerQuery = `
      	update orgs set owner =
        	(select id from users where id = $1 and org = $2 and status = $3)
      	where id = $4
      	`

	result, updateErr := tx.Exec(ctx,
		updateOwnerQuery,
		newOwner.String(),
		o.ID.String(),
		models.StatusActive,
		o.ID.String(),
	)

	if updateErr != nil {
		if models.NotNullConstraint(updateErr) {
			// if strings.Contains(strings.ToLower(updateErr.Error()), "constraint") {
			// the prospective new owner wasn't
			// (1) found AND
			// (2) in the org AND
			// (3) active
			// which would result in NULL as the attempted new
			// value for the owner, which violates the NOT NULL constraint
			return models.ErrRelatedUser
		}
		return updateErr
	}

	updated := result.RowsAffected()
	if updated != 1 {
		return models.ErrRowsAffected
	}

	refreshErr := o.Refresh(ctx, tx.Conn())
	if refreshErr != nil {
		return refreshErr
	}

	auditErr := audit.Insert(ctx, tx.Conn(), audit.OrgOwner, "orgs", o.ID)
	if auditErr != nil {
		return auditErr
	}

	return tx.Commit(ctx)
}

// UpdateStatus changes the org status.
func (o *Org) UpdateStatus(ctx context.Context,
	conn *pgx.Conn,
	newStatus models.Status,
) error {
	tx, txErr := conn.Begin(ctx)
	if txErr != nil {
		return txErr
	}
	defer tx.Rollback(ctx) // nolint:errcheck

	statusUpdateErr := models.Update(context.Background(),
		tx.Conn(),
		"orgs",
		o.ID,
		"status",
		newStatus)
	if statusUpdateErr != nil {
		return statusUpdateErr
	}

	refreshErr := o.Refresh(ctx, tx.Conn())
	if refreshErr != nil {
		return refreshErr
	}

	auditErr := audit.Insert(ctx, tx.Conn(), audit.Status, "orgs", o.ID)
	if auditErr != nil {
		return auditErr
	}

	return tx.Commit(ctx)
}
