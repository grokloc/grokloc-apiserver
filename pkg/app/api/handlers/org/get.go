package org

import (
	// "context"
	"errors"
	"net/http"

	"github.com/grokloc/grokloc-apiserver/pkg/app"

	"github.com/grokloc/grokloc-apiserver/pkg/app/admin/org"
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
			auth == withuser.AuthOrg &&
				withuser.GetOrg(r).GetID() == withmodel.GetModelWithOrg(r).GetOrg()
		if !authOK {
			logger.Debug("expected auth level not satisfied",
				"err", app.ErrorInadequateAuthorization)
			http.Error(w, app.ErrorInadequateAuthorization.Error(), http.StatusForbidden)
			return
		}

		modelObject := withmodel.GetModelAny(r)
		o, ok := modelObject.(*org.Org)
		if !ok {
			logger.Error("coerce model to *org.Org", "err", errors.New("withmodel middleware cached object not coerced to *org.Org"))
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		render.JSON(w, logger, o)
	}
}
