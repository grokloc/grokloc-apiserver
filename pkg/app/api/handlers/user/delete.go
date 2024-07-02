package user

import (
	"context"
	"errors"
	"net/http"

	"github.com/grokloc/grokloc-apiserver/pkg/app"
	"github.com/grokloc/grokloc-apiserver/pkg/app/admin/user"
	"github.com/grokloc/grokloc-apiserver/pkg/app/api/middlewares/request"
	"github.com/grokloc/grokloc-apiserver/pkg/app/api/middlewares/withmodel"
	"github.com/grokloc/grokloc-apiserver/pkg/app/models"
)

// Delete updates a user to have status inactive.
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

		modelObject := withmodel.GetModelAny(r)
		u, ok := modelObject.(*user.User)
		if !ok {
			logger.Error("coerce model to *user.User", "err", errors.New("withmodel middleware cached object not coerced to *user.User"))
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		execUpdateCtx, execUpdateCtxCancel := context.WithTimeout(context.Background(), st.ExecTimeout)
		defer execUpdateCtxCancel()
		putErr := u.UpdateStatus(execUpdateCtx, conn.Conn(), st.VersionKey, models.StatusInactive)
		if putErr != nil {
			logger.Error("user delete", "err", putErr)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusNoContent)
	}
}
