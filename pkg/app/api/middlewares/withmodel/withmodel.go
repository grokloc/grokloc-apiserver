package withmodel

import (
	"context"
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/grokloc/grokloc-apiserver/pkg/app"
	"github.com/grokloc/grokloc-apiserver/pkg/app/api/middlewares/request"
	"github.com/grokloc/grokloc-apiserver/pkg/app/models"
)

type IDType string

var IDKey = IDType("modelID")

// Middleware extracts the /{id} set in the router and turns it into
// a context variable of type models.ID.
func Middleware(st *app.State, kind models.Kind) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		fn := func(w http.ResponseWriter, r *http.Request) {
			logger := request.GetLogger(r)
			pathIDStr := chi.URLParam(r, "id")
			if len(pathIDStr) == 0 {
				logger.Error("router does not capture id")
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}

			pathID := new(models.ID)
			scanErr := pathID.Scan(pathIDStr)
			if scanErr != nil {
				logger.Debug("scan id", "err", scanErr)
				http.Error(w, "missing or malformed id in path", http.StatusBadRequest)
				return
			}

			r = r.WithContext(context.WithValue(r.Context(), IDKey, *pathID))

			newLogger := logger.With(
				slog.String("pathid", pathID.String()),
			)
			r = r.WithContext(context.WithValue(r.Context(), request.LoggerKey, newLogger))

			next.ServeHTTP(w, r)
		}
		return http.HandlerFunc(fn)
	}
}

// GetID returns the modelID. Panic indicates coding error.
func GetID(r *http.Request) models.ID {
	v := r.Context().Value(IDKey)
	if v == nil {
		panic("retrieve modelID from context")
	}
	modelID, a := v.(models.ID)
	if !a {
		panic("assert modelID -> models.ID")
	}
	return modelID
}
