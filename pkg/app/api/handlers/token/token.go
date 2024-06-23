package token

import (
	"fmt"
	"net/http"

	"github.com/grokloc/grokloc-apiserver/pkg/app"
	"github.com/grokloc/grokloc-apiserver/pkg/app/api/middlewares/auth/withuser"
	"github.com/grokloc/grokloc-apiserver/pkg/app/api/middlewares/request"
	"github.com/grokloc/grokloc-apiserver/pkg/app/api/render"
	"github.com/grokloc/grokloc-apiserver/pkg/app/jwt"
)

// JSONToken encodes a token for delivery to a client.
type JSONToken struct {
	Token string `json:"token"`
}

// Post provides a new token.
// Assumes request and withuser middlewares.
func Post(st *app.State) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		logger := request.GetLogger(r)

		tokenRequest := r.Header.Get(app.TokenRequestHeader)
		if len(tokenRequest) == 0 {
			logger.Debug("malformed request", "missing header", app.TokenRequestHeader)
			http.Error(w, fmt.Sprintf("missing header %s", app.TokenRequestHeader), http.StatusBadRequest)
			return
		}

		u := withuser.GetUser(r)
		if !jwt.VerifyTokenRequest(u.ID, u.APISecret.String(), tokenRequest) {
			w.Header().Set("WWW-Authenticate", "set token request correctly")
			http.Error(w, "token request failed", http.StatusUnauthorized)
			return
		}

		// see jet.go New() for explanation of use of tokenRequest here
		token, tokenErr := jwt.New(tokenRequest, st.SigningKey)
		if tokenErr != nil {
			logger.Error("jwt construction", "err", tokenErr)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		// do not set http 201 since there is no server-side entity created
		render.JSON(w, logger, JSONToken{Token: token})
	}
}
