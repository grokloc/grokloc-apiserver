package api

import (
	chi "github.com/go-chi/chi/v5"
	"github.com/grokloc/grokloc-apiserver/pkg/app"
	"github.com/grokloc/grokloc-apiserver/pkg/app/api/handlers/ok"
	"github.com/grokloc/grokloc-apiserver/pkg/app/api/handlers/org"
	"github.com/grokloc/grokloc-apiserver/pkg/app/api/handlers/token"
	"github.com/grokloc/grokloc-apiserver/pkg/app/api/handlers/user"
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
			rtr.With(withuser.RequireOneOf(
				withuser.AuthRoot,
			)).
				With(body.Middleware()).
				Post("/", org.Post(st))

			rtr.Route("/{id}", func(rtr chi.Router) {
				rtr.Use(withmodel.Middleware(st, models.KindOrg))
				rtr.With(withuser.RequireOneOf(
					withuser.AuthRoot,
					withuser.AuthOrg,
				)).
					Get("/", org.Get(st))

				rtr.Group(func(rtr chi.Router) {
					rtr.Use(withuser.RequireOneOf(withuser.AuthRoot))
					rtr.With(body.Middleware()).Put("/", org.Put(st))
					rtr.Delete("/", org.Delete(st))
				})
			})
		})

		// user related
		rtr.Route("/user", func(rtr chi.Router) {
			rtr.With(withuser.RequireOneOf(
				withuser.AuthRoot,
				withuser.AuthOrg,
			)).
				With(body.Middleware()).
				Post("/", user.Post(st))

			rtr.Route("/{id}", func(rtr chi.Router) {
				rtr.Use(withmodel.Middleware(st, models.KindUser))

				// Get, Put, Delete handlers call GetUserScopedAuth
				// to assert access
				rtr.Get("/", user.Get(st))
				rtr.Delete("/", user.Delete(st))
				rtr.With(body.Middleware()).Put("/", user.Put(st))
			})
		})
	})

	return rtr
}
