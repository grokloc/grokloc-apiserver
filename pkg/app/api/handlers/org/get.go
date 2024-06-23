package org

import (
	// "context"
	"errors"
	"net/http"

	"github.com/grokloc/grokloc-apiserver/pkg/app"

	"github.com/grokloc/grokloc-apiserver/pkg/app/admin/org"
	// "github.com/grokloc/grokloc-apiserver/pkg/app/api/middlewares/auth/withuser"
	"github.com/grokloc/grokloc-apiserver/pkg/app/api/middlewares/auth/withuser"
	"github.com/grokloc/grokloc-apiserver/pkg/app/api/middlewares/request"
	"github.com/grokloc/grokloc-apiserver/pkg/app/api/middlewares/withmodel"
	"github.com/grokloc/grokloc-apiserver/pkg/app/api/render"
	// "github.com/grokloc/grokloc-apiserver/pkg/app/models"
)

func Get(st *app.State) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		logger := request.GetLogger(r)
		modelObject := withmodel.GetModelAny(r)
		o, ok := modelObject.(*org.Org)
		if !ok {
			logger.Error("coerce model to *org.Org", "err", errors.New("withmodel middleware cached object not coerced to *org.Org"))
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		// acquireCtx, acquireCancel := context.WithTimeout(context.Background(), st.ConnTimeout)
		// defer acquireCancel()
		// conn, connErr := st.RandomReplica().Acquire(acquireCtx)
		// if connErr != nil {
		// 	logger.Error("acquire replica conn", "err", connErr)
		// 	http.Error(w, "internal error", http.StatusInternalServerError)
		// 	return
		// }
		// defer conn.Release()

		// execCtx, execCtxCancel := context.WithTimeout(context.Background(), st.ExecTimeout)
		// defer execCtxCancel()

		// o, oErr := org.Read(execCtx, conn.Conn(), withmodel.GetID(r))
		// if oErr != nil {
		// 	if oErr == models.ErrNotFound {
		// 		http.Error(w, "not found", http.StatusNotFound)
		// 		return
		// 	}
		// 	logger.Error("org read", "err", oErr)
		// 	http.Error(w, "internal error", http.StatusInternalServerError)
		// 	return
		// }

		// router guarantees caller is root or org owner, but if org owner, must
		// assure that calling user is owner of org specified in path
		// todo: replace this with proper RequireOneOf(...AuthOrg...) support
		if withuser.GetAuth(r) == withuser.AuthOrg {
			if withuser.GetUser(r).Org != o.ID {
				logger.Debug("not owner of org",
					"err", app.ErrorInadequateAuthorization)
				http.Error(w, app.ErrorInadequateAuthorization.Error(), http.StatusForbidden)
				return
			}
		}

		render.JSON(w, logger, o)
	}
}
