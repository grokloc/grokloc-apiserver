package org

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/grokloc/grokloc-apiserver/pkg/app"
	"github.com/grokloc/grokloc-apiserver/pkg/app/admin/org"
	"github.com/grokloc/grokloc-apiserver/pkg/app/api/middlewares/body"
	"github.com/grokloc/grokloc-apiserver/pkg/app/api/middlewares/request"
	"github.com/grokloc/grokloc-apiserver/pkg/app/api/render"
	"github.com/grokloc/grokloc-apiserver/pkg/app/models"
)

func Post(st *app.State) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		logger := request.GetLogger(r)

		ev, evErr := org.NewCreateEvent(&st.Argon2Config)
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
			http.Error(w, "org create json malformed", http.StatusBadRequest)
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
		o, _, createErr := org.Create(
			execCtx,
			conn.Conn(),
			ev.Name,
			ev.OwnerDisplayName,
			ev.OwnerEmail,
			ev.OwnerPassword,
			st.DefaultRole,
			st.VersionKey,
		)

		if createErr != nil {
			if createErr == models.ErrConflict {
				logger.Debug("create org", "err", createErr)
				http.Error(w, "org name in use", http.StatusConflict)
				return
			}
			logger.Error("create org", "err", createErr)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		w.Header().Set("location", app.APIPath+st.APIVersion+"/org/"+o.ID.String())
		w.WriteHeader(http.StatusCreated)
		render.JSON(w, logger, o)
	}
}
