package org

import (
	"context"
	"net/http"

	"github.com/grokloc/grokloc-apiserver/pkg/app"
	"github.com/grokloc/grokloc-apiserver/pkg/app/admin/org"
	"github.com/grokloc/grokloc-apiserver/pkg/app/api/middlewares/request"
	"github.com/grokloc/grokloc-apiserver/pkg/app/api/middlewares/withmodel"
	"github.com/grokloc/grokloc-apiserver/pkg/app/models"
)

func Delete(st *app.State) http.HandlerFunc {
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

		execUpdateCtx, execUpdateCtxCancel := context.WithTimeout(context.Background(), st.ExecTimeout)
		defer execUpdateCtxCancel()
		putErr := o.UpdateStatus(execUpdateCtx, conn.Conn(), models.StatusInactive)
		if putErr != nil {
			logger.Error("org delete", "err", putErr)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusNoContent)
	}
}
