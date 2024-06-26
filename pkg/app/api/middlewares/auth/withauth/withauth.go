package withauth

import (
	"net/http"

	"github.com/grokloc/grokloc-apiserver/pkg/app"
	"github.com/grokloc/grokloc-apiserver/pkg/app/api/middlewares/auth/withuser"
	"github.com/grokloc/grokloc-apiserver/pkg/app/api/middlewares/request"
	"github.com/grokloc/grokloc-apiserver/pkg/app/api/middlewares/withmodel"
)

func RequireOneOf(levels ...withuser.AuthLevel) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		fn := func(w http.ResponseWriter, r *http.Request) {
			if len(levels) == 0 {
				panic("no expected auth levels provided")
			}

			satisfied := false
			auth := withuser.GetAuth(r)

			// no matter what requirements are in place, root
			// can always access the resource
			// root is satisfied without checking a model,
			// so level AuthRoot does not require withmodel
			// middleware to be called prior
			if auth == withuser.AuthRoot {
				satisfied = true
			}

			// all other levels require inspecting a loaded model for
			// authorization metadata to check, so withmodel middleware
			// must be called prior if using any of the following levels
			if !satisfied {
				for _, level := range levels {
					if level == withuser.AuthOrg && auth == withuser.AuthOrg {
						if withuser.GetOrg(r).GetOrg() == withmodel.GetModelWithOrg(r).GetOrg() {
							// is org owner for org related to model resource
							satisfied = true
							break
						}
					} else if level == withuser.AuthUser && auth == withuser.AuthUser {
						if withuser.GetUser(r).GetID() == withmodel.GetModelWithID(r).GetID() {
							// model is the user themselves
							satisfied = true
							break
						}
					} else if level == withuser.AuthPeer && auth == withuser.AuthUser {
						if withuser.GetUser(r).GetOrg() == withmodel.GetModelWithOrg(r).GetOrg() {
							// in same org as model resource
							satisfied = true
							break
						}
					}
				}
			}

			if !satisfied {
				logger := request.GetLogger(r)
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
