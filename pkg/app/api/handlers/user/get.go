package user

import (
	"errors"
	"net/http"

	"github.com/grokloc/grokloc-apiserver/pkg/app"
	"github.com/grokloc/grokloc-apiserver/pkg/app/admin/user"
	"github.com/grokloc/grokloc-apiserver/pkg/app/api/middlewares/auth/withuser"
	"github.com/grokloc/grokloc-apiserver/pkg/app/api/middlewares/request"
	"github.com/grokloc/grokloc-apiserver/pkg/app/api/middlewares/withmodel"
	"github.com/grokloc/grokloc-apiserver/pkg/app/api/render"
)

func Get(st *app.State) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		logger := request.GetLogger(r)

		auth := withuser.GetAuth(r)
		authOK := auth == withuser.AuthRoot ||
			// org owner, user to be viewed is in org
			auth == withuser.AuthOrg && withuser.GetOrg(r).GetID() == withmodel.GetModelWithOrg(r).GetOrg() ||
			// user viewing themselves
			auth == withuser.AuthUser && withuser.GetUser(r).GetID() == withmodel.GetModelWithID(r).GetID()
		if !authOK {
			logger.Debug("expected auth level not satisfied",
				"err", app.ErrorInadequateAuthorization)
			http.Error(w, app.ErrorInadequateAuthorization.Error(), http.StatusForbidden)
			return
		}

		modelObject := withmodel.GetModelAny(r)
		u, ok := modelObject.(*user.User)
		if !ok {
			logger.Error("coerce model to *user.User", "err", errors.New("withmodel middleware cached object not coerced to *user.User"))
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		render.JSON(w, logger, u)
	}
}
