package withmodel

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/grokloc/grokloc-apiserver/pkg/app"
	"github.com/grokloc/grokloc-apiserver/pkg/app/admin/org"
	"github.com/grokloc/grokloc-apiserver/pkg/app/admin/user"
	"github.com/grokloc/grokloc-apiserver/pkg/app/api/middlewares/request"
	"github.com/grokloc/grokloc-apiserver/pkg/app/models"
)

type IDType string

var IDKey = IDType("modelID")

type ModelType string

var ModelKey = ModelType("modelObject")

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

			acquireCtx, acquireCancel := context.WithTimeout(context.Background(), st.ConnTimeout)
			defer acquireCancel()
			conn, connErr := st.RandomReplica().Acquire(acquireCtx)
			if connErr != nil {
				logger.Error("acquire replica conn", "err", connErr)
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}
			defer conn.Release()

			execCtx, execCtxCancel := context.WithTimeout(context.Background(), st.ExecTimeout)
			defer execCtxCancel()

			// read in the model object based on its kind
			var readErr error
			var readModel any
			switch kind {
			case models.KindOrg:
				readModel, readErr = org.Read(execCtx, conn.Conn(), *pathID)
			case models.KindUser:
				readModel, readErr = user.Read(execCtx, conn.Conn(), st.VersionKey, *pathID)
			default:
				logger.Error("unknown kind", "err", fmt.Errorf("kind: %v", kind))
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}

			if readErr != nil {
				if readErr == models.ErrNotFound {
					http.Error(w, "not found", http.StatusNotFound)
					return
				}
				logger.Error("model read", "err", readErr)
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}

			r = r.WithContext(context.WithValue(r.Context(), IDKey, *pathID))
			r = r.WithContext(context.WithValue(r.Context(), ModelKey, readModel))

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

// GetWithOrg returns the model object as a models.WithOrg instance.
// Panic indicates coding error.
func GetModelWithOrg(r *http.Request) models.WithOrg {
	v := r.Context().Value(ModelKey)
	if v == nil {
		panic("retrieve modelObject from context")
	}
	modelWithOrg, a := v.(models.WithOrg)
	if !a {
		panic("assert modelObject -> models.WithOrg")
	}
	return modelWithOrg
}

// GetWithUser returns the model object as a models.WithUser instance.
// Panic indicates coding error.
func GetModelWithUser(r *http.Request) models.WithUser {
	v := r.Context().Value(ModelKey)
	if v == nil {
		panic("retrieve modelObject from context")
	}
	modelWithUser, a := v.(models.WithUser)
	if !a {
		panic("assert modelObject -> models.WithUser")
	}
	return modelWithUser
}

// GetWithID returns the model object as a models.WithID instance.
// Panic indicates coding error.
func GetModelWithID(r *http.Request) models.WithID {
	v := r.Context().Value(ModelKey)
	if v == nil {
		panic("retrieve modelObject from context")
	}
	modelWithID, a := v.(models.WithID)
	if !a {
		panic("assert modelObject -> models.WithID")
	}
	return modelWithID
}

// GetModelAny returns the model object as any.
// Panic indicates coding error.
func GetModelAny(r *http.Request) any {
	v := r.Context().Value(ModelKey)
	if v == nil {
		panic("retrieve modelObject from context")
	}
	return v
}
