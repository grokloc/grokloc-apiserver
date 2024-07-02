package withauth

import (
	"net/http"

	"github.com/grokloc/grokloc-apiserver/pkg/app"
	"github.com/grokloc/grokloc-apiserver/pkg/app/api/middlewares/auth/withuser"
	"github.com/grokloc/grokloc-apiserver/pkg/app/api/middlewares/request"
	"github.com/grokloc/grokloc-apiserver/pkg/app/api/middlewares/withmodel"
)

// RequireOneOf provides simple auth filtering based on auth levels.
func RequireOneOf(st *app.State, levels ...withuser.AuthLevel) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		fn := func(w http.ResponseWriter, r *http.Request) {
			logger := request.GetLogger(r)

			auth := withuser.GetAuth(r)

			satisfied := false
			for _, level := range levels {
				if (level == withuser.AuthRoot && auth == withuser.AuthRoot) ||
					// AuthOrg level, calling user has auth level AuthOrg and
					// calling user's org is the same as the org for the model
					(level == withuser.AuthOrg && auth == withuser.AuthOrg &&
						withmodel.GetModelWithOrg(r).GetOrg() == withuser.GetOrg(r).ID) ||
					// AuthUser level, calling user has auth level AuthUser and
					// calling user's ID is the same as the user for the model
					(level == withuser.AuthUser && auth == withuser.AuthUser &&
						withmodel.GetModelWithUser(r).GetUser() == withuser.GetUser(r).ID) ||
					// AuthPeer level, calling user has auth level AuthUser and
					// calling user's org is the same as the org for the model
					// (calling user is a peer in the same org)
					(level == withuser.AuthPeer && auth == withuser.AuthUser &&
						withmodel.GetModelWithOrg(r).GetOrg() == withuser.GetOrg(r).ID) {
					satisfied = true
					break
				}
			}

			if !satisfied {
				logger.Debug("expected auth level not satisfied",
					"err", app.ErrorInadequateAuthorization)
				http.Error(w, app.ErrorInadequateAuthorization.Error(), http.StatusForbidden)
				return
			}

			next.ServeHTTP(w, r)
		}
		return http.HandlerFunc(fn)
	}
}
