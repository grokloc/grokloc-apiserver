package withuser

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/grokloc/grokloc-apiserver/pkg/app"
	"github.com/grokloc/grokloc-apiserver/pkg/app/admin/org"
	"github.com/grokloc/grokloc-apiserver/pkg/app/admin/user"
	"github.com/grokloc/grokloc-apiserver/pkg/app/api/middlewares/request"
	"github.com/grokloc/grokloc-apiserver/pkg/app/models"
)

type OrgType string

var OrgKey = OrgType("org")

type UserType string

var UserKey = UserType("user")

type AuthType string

var AuthKey = AuthType("auth")

type AuthLevel int

var ErrorAuthLevelInvalid = errors.New("auth level invalid")

const (
	AuthNone = AuthLevel(0)
	AuthUser = AuthLevel(1)
	AuthOrg  = AuthLevel(2)
	AuthRoot = AuthLevel(3)
	AuthPeer = AuthLevel(4)
)

func newAuthLevel(authLevel int) (AuthLevel, error) {
	switch authLevel {
	case 1:
		return AuthUser, nil
	case 2:
		return AuthOrg, nil
	case 3:
		return AuthRoot, nil
	case 4:
		return AuthPeer, nil
	default:
		return AuthNone, ErrorAuthLevelInvalid
	}
}

// Middleware checks user and org for the incoming request,
// as indicated by the x-grokloc-id header.
// Following this middleware, the caller's user and org
// info are available from the request context.
func Middleware(st *app.State) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		fn := func(w http.ResponseWriter, r *http.Request) {
			logger := request.GetLogger(r)

			userIDStr := r.Header.Get(app.IDHeader)
			if len(userIDStr) == 0 {
				logger.Debug("malformed request", "missing header", app.IDHeader)
				http.Error(w, fmt.Sprintf("missing header %s", app.IDHeader), http.StatusBadRequest)
				return
			}
			userID := new(models.ID)
			scanErr := userID.Scan(userIDStr)
			if scanErr != nil {
				logger.Debug("malformed request",
					"malformed header", app.IDHeader,
					"err", scanErr,
				)
				http.Error(w, fmt.Sprintf("malformed header %s", app.IDHeader), http.StatusBadRequest)
				return
			}

			replica := st.RandomReplica()
			conn, connErr := replica.Acquire(r.Context())
			if connErr != nil {
				logger.Error("acquire replica conn", "err", connErr)
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}
			defer conn.Release()
			u, userReadErr := user.Read(r.Context(), conn.Conn(), st.VersionKey, *userID)
			if userReadErr == models.ErrNotFound {
				logger.Debug("not found", "user", userIDStr)
				http.Error(w, "user not found", http.StatusNotFound)
				return
			}
			if userReadErr != nil {
				logger.Error("user read",
					"user", userIDStr,
					"err", userReadErr,
				)
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}
			if u.Meta.Status != models.StatusActive {
				logger.Debug("user not active", "user", userIDStr)
				http.Error(w, "user not active", http.StatusBadRequest)
			}

			o, orgReadErr := org.Read(r.Context(), conn.Conn(), u.Org)
			if orgReadErr == models.ErrNotFound {
				logger.Debug("org not found", "org", u.Org.String())
				http.Error(w, "org not found", http.StatusBadRequest)
				return
			}
			if orgReadErr != nil {
				logger.Error("org read",
					"org", u.Org.String(),
					"err", orgReadErr,
				)
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}
			if o.Meta.Status != models.StatusActive {
				logger.Debug("org not active", "org", u.Org.String())
				http.Error(w, "org not active", http.StatusBadRequest)
			}

			r = r.WithContext(context.WithValue(r.Context(), OrgKey, o))
			r = r.WithContext(context.WithValue(r.Context(), UserKey, u))

			authLevel := AuthUser
			if o.Owner == u.ID {
				authLevel = AuthOrg
			}
			// root user is also the owner of the root org,
			// so at this point the root user has AuthOrg;
			// test again for root
			if u.ID == st.Root.ID {
				authLevel = AuthRoot
			}
			r = r.WithContext(context.WithValue(r.Context(), AuthKey, authLevel))

			newLogger := logger.With(slog.Group("bio",
				slog.String("org", o.ID.String()),
				slog.String("user", u.ID.String()),
			))
			r = r.WithContext(context.WithValue(r.Context(), request.LoggerKey, newLogger))

			next.ServeHTTP(w, r)
		}
		return http.HandlerFunc(fn)
	}
}

// GetOrg returns the org. Panic indicates coding error.
func GetOrg(r *http.Request) *org.Org {
	v := r.Context().Value(OrgKey)
	if v == nil {
		panic("retrieve org value from context")
	}
	o, a := v.(*org.Org)
	if !a {
		panic("assert *org.Org")
	}
	return o
}

// GetUser returns the user. Panic indicates coding error.
func GetUser(r *http.Request) *user.User {
	v := r.Context().Value(UserKey)
	if v == nil {
		panic("retrieve user value from context")
	}
	u, a := v.(*user.User)
	if !a {
		panic("assert *user.User")
	}
	return u
}

// GetAuth returns the auth level int. Panic indicates coding error.
func GetAuth(r *http.Request) AuthLevel {
	v := r.Context().Value(AuthKey)
	if v == nil {
		panic("retrieve auth value from context")
	}
	l, a := v.(AuthLevel)
	if !a {
		panic("assert AuthLevel")
	}
	_, levelErr := newAuthLevel(int(l))
	if levelErr != nil {
		panic("invalid auth level used")
	}
	return l
}
