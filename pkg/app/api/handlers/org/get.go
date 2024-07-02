package org

import (
	"errors"
	"net/http"

	"github.com/grokloc/grokloc-apiserver/pkg/app"

	"github.com/grokloc/grokloc-apiserver/pkg/app/admin/org"
	"github.com/grokloc/grokloc-apiserver/pkg/app/api/middlewares/request"
	"github.com/grokloc/grokloc-apiserver/pkg/app/api/middlewares/withmodel"
	"github.com/grokloc/grokloc-apiserver/pkg/app/api/render"
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

		render.JSON(w, logger, o)
	}
}
