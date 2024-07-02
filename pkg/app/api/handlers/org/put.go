package org

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/grokloc/grokloc-apiserver/pkg/app"
	"github.com/grokloc/grokloc-apiserver/pkg/app/admin/org"
	"github.com/grokloc/grokloc-apiserver/pkg/app/api/middlewares/body"
	"github.com/grokloc/grokloc-apiserver/pkg/app/api/middlewares/request"
	"github.com/grokloc/grokloc-apiserver/pkg/app/api/middlewares/withmodel"
	"github.com/grokloc/grokloc-apiserver/pkg/app/api/render"
	"github.com/grokloc/grokloc-apiserver/pkg/app/models"
)

func decodeToUpdateStatusEvent(body []byte, v *org.UpdateStatusEvent) bool {
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	return decoder.Decode(v) == nil
}

func decodeToUpdateOwnerEvent(body []byte, v *org.UpdateOwnerEvent) bool {
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	return decoder.Decode(v) == nil
}

func Put(st *app.State) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		logger := request.GetLogger(r)

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

		o, oErr := org.Read(execCtx, conn.Conn(), withmodel.GetID(r))
		if oErr != nil {
			if oErr == models.ErrNotFound {
				http.Error(w, "not found", http.StatusNotFound)
				return
			}
			logger.Error("org read", "err", oErr)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		updateCtx, updateCtxCancel := context.WithTimeout(context.Background(), st.ExecTimeout)
		defer updateCtxCancel()
		var updateErr error

		var updateStatusEvent org.UpdateStatusEvent
		var updateOwnerEvent org.UpdateOwnerEvent

		bs := body.GetBody(r)

		if decodeToUpdateStatusEvent(bs, &updateStatusEvent) {
			updateErr = o.UpdateStatus(updateCtx, conn.Conn(), updateStatusEvent.Status)
		} else if decodeToUpdateOwnerEvent(bs, &updateOwnerEvent) {
			updateErr = o.UpdateOwner(updateCtx, conn.Conn(), updateOwnerEvent.Owner)
			// the new owner does not meet the criteria of being in org and active
			if updateErr != nil && updateErr == models.ErrRelatedUser {
				logger.Debug("new org owner is not active and in org", "err", updateErr)
				http.Error(w, "suggested new owner is not in org and active", http.StatusBadRequest)
				return
			}
		} else {
			logger.Debug("no matching event", "err", errors.New("put event"))
			http.Error(w, "body does not describe any org update", http.StatusBadRequest)
			return
		}

		if updateErr != nil {
			logger.Error("org update", "err", updateErr)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		render.JSON(w, logger, o)
	}
}
