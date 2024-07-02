package api

import (
	chi "github.com/go-chi/chi/v5"
	"github.com/grokloc/grokloc-apiserver/pkg/app"
	"github.com/grokloc/grokloc-apiserver/pkg/app/api/handlers/ok"
	"github.com/grokloc/grokloc-apiserver/pkg/app/api/handlers/org"
	"github.com/grokloc/grokloc-apiserver/pkg/app/api/handlers/token"
	"github.com/grokloc/grokloc-apiserver/pkg/app/api/handlers/user"
	"github.com/grokloc/grokloc-apiserver/pkg/app/api/middlewares/auth/withauth"
	"github.com/grokloc/grokloc-apiserver/pkg/app/api/middlewares/auth/withtoken"
	"github.com/grokloc/grokloc-apiserver/pkg/app/api/middlewares/auth/withuser"
	"github.com/grokloc/grokloc-apiserver/pkg/app/api/middlewares/body"
	"github.com/grokloc/grokloc-apiserver/pkg/app/api/middlewares/request"
	"github.com/grokloc/grokloc-apiserver/pkg/app/api/middlewares/withmodel"
	"github.com/grokloc/grokloc-apiserver/pkg/app/models"
	"github.com/rs/cors"
)

// NewRouter creates a new chi routing table for the api.
func NewRouter(st *app.State) *chi.Mux {
	rtr := chi.NewRouter()
	rtr.Use(cors.Default().Handler)
	rtr.Use(request.Middleware(st))

	// unversioned routes

	// liveness testing
	rtr.Get("/ok", ok.Get())

	// validated users can get a token
	rtr.Route("/token", func(rtr chi.Router) {
		rtr.Use(withuser.Middleware(st))
		rtr.Post("/", token.Post(st))
	})

	// versioned api routes

	// all require user+token validation
	rtr.Route(app.APIPath+st.APIVersion, func(rtr chi.Router) {
		rtr.Use(withuser.Middleware(st))
		rtr.Use(withtoken.Middleware(st))

		// useful for testing auth
		rtr.Get("/ok", ok.Get())

		// org related
		rtr.Route("/org", func(rtr chi.Router) {
			rtr.With(body.Middleware()).
				With(withauth.RequireOneOf(st, withuser.AuthRoot)).
				Post("/", org.Post(st))

			rtr.Route("/{id}", func(rtr chi.Router) {
				rtr.Use(withmodel.Middleware(st, models.KindOrg))
				rtr.Group(func(rtr chi.Router) {
					rtr.Use(withauth.RequireOneOf(st, withuser.AuthRoot, withuser.AuthOrg))

					rtr.Get("/", org.Get(st))

					rtr.Get("/users", org.Users(st))
				})
				rtr.Group(func(rtr chi.Router) {
					rtr.Use(withauth.RequireOneOf(st, withuser.AuthRoot))

					rtr.Delete("/", org.Delete(st))

					rtr.With(body.Middleware()).
						Put("/", org.Put(st))
				})
			})
		})

		// user related
		rtr.Route("/user", func(rtr chi.Router) {
			rtr.With(body.Middleware()).
				Post("/", user.Post(st)) // auth enforced in handler

			rtr.Route("/{id}", func(rtr chi.Router) {
				rtr.Use(withmodel.Middleware(st, models.KindUser))

				rtr.With(withauth.RequireOneOf(st, withuser.AuthRoot, withuser.AuthOrg, withuser.AuthUser)).
					Get("/", user.Get(st))

				rtr.With(withauth.RequireOneOf(st, withuser.AuthRoot, withuser.AuthOrg)).
					Delete("/", user.Delete(st))

				rtr.With(body.Middleware()).
					With(withauth.RequireOneOf(st, withuser.AuthRoot, withuser.AuthOrg, withuser.AuthUser)).
					Put("/", user.Put(st)) // some refined auth rules in handler
			})
		})
	})

	return rtr
}
