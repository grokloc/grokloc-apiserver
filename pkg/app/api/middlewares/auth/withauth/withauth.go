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

			if auth == withuser.AuthRoot {
				// root can do anything
				satisfied = true
			}

			if !satisfied {
				for _, level := range levels {
					if level == withuser.AuthOrg && auth == withuser.AuthOrg {
						if withuser.GetOrg(r).GetOrg() == withmodel.GetModelWithOrg(r).GetOrg() {
							satisfied = true
							break
						}
					} else if level == withuser.AuthUser && auth == withuser.AuthUser {
						if withuser.GetUser(r).GetID() == withmodel.GetModelWithID(r).GetID() {
							satisfied = true
							break
						}
					} else if level == withuser.AuthTeammate && auth == withuser.AuthUser {
						if withuser.GetUser(r).GetOrg() == withmodel.GetModelWithOrg(r).GetOrg() {
							// in same org
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
