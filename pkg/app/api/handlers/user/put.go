package user

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/grokloc/grokloc-apiserver/pkg/app"
	"github.com/grokloc/grokloc-apiserver/pkg/app/admin/user"
	"github.com/grokloc/grokloc-apiserver/pkg/app/api/middlewares/auth/withuser"
	"github.com/grokloc/grokloc-apiserver/pkg/app/api/middlewares/body"
	"github.com/grokloc/grokloc-apiserver/pkg/app/api/middlewares/request"
	"github.com/grokloc/grokloc-apiserver/pkg/app/api/middlewares/withmodel"
	"github.com/grokloc/grokloc-apiserver/pkg/app/api/render"
	"github.com/grokloc/grokloc-apiserver/pkg/security"
)

func decodeToUpdateStatusEvent(body []byte, v *user.UpdateStatusEvent) bool {
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	return decoder.Decode(v) == nil
}

func decodeToUpdateAPISecretEvent(body []byte, v *user.UpdateAPISecretEvent) bool {
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	return decoder.Decode(v) == nil
}

func decodeToUpdateDisplayNameEvent(body []byte, v *user.UpdateDisplayNameEvent) bool {
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	return decoder.Decode(v) == nil
}

func decodeToUpdatePasswordEvent(body []byte, v *user.UpdatePasswordEvent) bool {
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	return decoder.Decode(v) == nil
}

func Put(st *app.State) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		logger := request.GetLogger(r)

		// some updates have special limitations on auth
		auth := withuser.GetAuth(r)

		modelObject := withmodel.GetModelAny(r)
		u, ok := modelObject.(*user.User)
		if !ok {
			logger.Error("coerce model to *user.User", "err", errors.New("withmodel middleware cached object not coerced to *user.User"))
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		acquireCtx, acquireCancel := context.WithTimeout(context.Background(), st.ConnTimeout)
		defer acquireCancel()
		conn, connErr := st.Master.Acquire(acquireCtx)
		if connErr != nil {
			logger.Error("acquire master conn", "err", connErr)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		defer conn.Release()

		var updateStatusEvent user.UpdateStatusEvent
		var updateAPISecretEvent user.UpdateAPISecretEvent
		var updateDisplayNameEvent user.UpdateDisplayNameEvent
		var updatePasswordEvent user.UpdatePasswordEvent

		updateCtx, updateCtxCancel := context.WithTimeout(context.Background(), st.ExecTimeout)
		defer updateCtxCancel()
		var updateErr error

		bs := body.GetBody(r)

		if decodeToUpdateStatusEvent(bs, &updateStatusEvent) {
			// only org owner or root can update a user status
			if auth == withuser.AuthUser {
				logger.Debug("not root or org owner at status update",
					"err", app.ErrorInadequateAuthorization)
				http.Error(w, app.ErrorInadequateAuthorization.Error(), http.StatusForbidden)
				return
			}
			updateErr = u.UpdateStatus(updateCtx, conn.Conn(), st.VersionKey, updateStatusEvent.Status)
		} else if decodeToUpdateAPISecretEvent(bs, &updateAPISecretEvent) {
			if !updateAPISecretEvent.GenerateAPISecret {
				// force caller to set field as a confirmation
				err := errors.New("GenerateAPISecret field must be set to true")
				logger.Debug("confirm missing", "err", err)
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			updateErr = u.UpdateAPISecret(updateCtx, conn.Conn(), st.VersionKey)
		} else if decodeToUpdateDisplayNameEvent(bs, &updateDisplayNameEvent) {
			updateErr = u.UpdateDisplayName(updateCtx, conn.Conn(), st.VersionKey, updateDisplayNameEvent.DisplayName)
		} else if decodeToUpdatePasswordEvent(bs, &updatePasswordEvent) {
			// any user can change their own password, including root and org owner
			// (root and org owner cannot change any other passwords)
			canChangePassword := withuser.GetUser(r).GetID() == withmodel.GetModelWithID(r).GetID()
			if !canChangePassword {
				logger.Debug("not self user at password update",
					"err", app.ErrorInadequateAuthorization)
				http.Error(w, app.ErrorInadequateAuthorization.Error(), http.StatusForbidden)
				return
			}
			// password is currently in plaintext, derive an argon2 password
			newPassword, newPasswordErr := security.DerivePassword(updatePasswordEvent.Password.String(), st.Argon2Config)
			if newPasswordErr != nil {
				logger.Error("derive password", "err", newPasswordErr)
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}
			// overwrite plaintext password so it is not available anymore
			updatePasswordEvent.Password = *newPassword
			updateErr = u.UpdatePassword(updateCtx, conn.Conn(), st.VersionKey, updatePasswordEvent.Password)
		} else {
			logger.Debug("no matching event", "err", errors.New("put event"))
			http.Error(w, "body does not describe any user update", http.StatusBadRequest)
			return
		}

		if updateErr != nil {
			logger.Error("user update", "err", updateErr)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		render.JSON(w, logger, u)
	}
}
