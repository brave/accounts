package controllers

import (
	"net/http"

	"github.com/brave-experiments/accounts/datastore"
	"github.com/brave-experiments/accounts/middleware"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/render"
)

type AuthController struct{}

func NewAuthController() *AuthController {
	return &AuthController{}
}

func (ac *AuthController) Router(authMiddleware func(http.Handler) http.Handler) chi.Router {
	r := chi.NewRouter()

	r.With(authMiddleware).Get("/auth/validate", ac.Validate)

	return r
}

// @Summary Validate auth token
// @Description Validates an auth token and returns session details
// @Tags Auth
// @Produce json
// @Param Authorization header string true "Bearer + auth token"
// @Success 200 {object} ValidateTokenResponse
// @Failure 401 {object} util.ErrorResponse
// @Failure 500 {object} util.ErrorResponse
// @Router /v2/auth/validate [get]
func (ac *AuthController) Validate(w http.ResponseWriter, r *http.Request) {
	session := r.Context().Value(middleware.ContextSession).(*datastore.Session)

	response := ValidateTokenResponse{
		Email:     session.Account.Email,
		AccountID: session.AccountID.String(),
		SessionID: session.ID.String(),
	}

	render.Status(r, http.StatusOK)
	render.JSON(w, r, response)
}
