// Package ok provides an unauthenticated healthcheck handler.
package ok

import (
	"net/http"

	"github.com/grokloc/grokloc-apiserver/pkg/app/api/middlewares/request"
	"github.com/grokloc/grokloc-apiserver/pkg/app/api/render"
)

type okResp struct {
	RequestID string `json:"request_id"`
}

// Get provides an unauthenticated ping service.
func Get() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		render.JSON(w, request.GetLogger(r), okResp{RequestID: request.GetID(r)})
	}
}
