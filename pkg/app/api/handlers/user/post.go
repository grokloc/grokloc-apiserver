package user

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/grokloc/grokloc-apiserver/pkg/app"
	"github.com/grokloc/grokloc-apiserver/pkg/app/admin/user"
	"github.com/grokloc/grokloc-apiserver/pkg/app/api/middlewares/auth/withuser"
	"github.com/grokloc/grokloc-apiserver/pkg/app/api/middlewares/body"
	"github.com/grokloc/grokloc-apiserver/pkg/app/api/middlewares/request"
	"github.com/grokloc/grokloc-apiserver/pkg/app/api/render"
	"github.com/grokloc/grokloc-apiserver/pkg/app/models"
)

func Post(st *app.State) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		logger := request.GetLogger(r)

		ev, evErr := user.NewCreateEvent(&st.Argon2Config)
		if evErr != nil {
			logger.Error("new create event", "err", evErr)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		// ev has custom UnmsarshalJSON, so do not use json.Decoder here
		// see CreateEvent.UnmarshalJSON
		umErr := json.Unmarshal(body.GetBody(r), &ev)
		if umErr != nil {
			logger.Debug("decode CreateEvent", "err", umErr)
			http.Error(w, "user create json malformed", http.StatusBadRequest)
			return
		}

		// if auth was org owner, then org ID must match org
		// provided in event
		// (had to decode body above to test this)
		auth := withuser.GetAuth(r)
		authOK := auth == withuser.AuthRoot ||
			auth == withuser.AuthOrg && ev.Org == withuser.GetOrg(r).GetID()
		if !authOK {
			logger.Debug("expected auth level not satisfied",
				"err", app.ErrorInadequateAuthorization)
			http.Error(w, app.ErrorInadequateAuthorization.Error(), http.StatusForbidden)
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

		execCtx, execCtxCancel := context.WithTimeout(context.Background(), st.ExecTimeout)
		defer execCtxCancel()

		u, createErr := user.Create(
			execCtx,
			conn.Conn(),
			ev.DisplayName,
			ev.Email,
			ev.Org,
			ev.Password,
			st.VersionKey,
		)
		if createErr != nil {
			if createErr == models.ErrConflict {
				logger.Debug("create err", "err", createErr)
				http.Error(w, "email already in use in org", http.StatusConflict)
				return
			}
			logger.Error("create err", "err", createErr)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		w.Header().Set("location", app.APIPath+st.APIVersion+"/user/"+u.ID.String())
		w.WriteHeader(http.StatusCreated)
		render.JSON(w, logger, u)
	}
}
