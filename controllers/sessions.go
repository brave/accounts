package controllers

import (
	"errors"
	"net/http"

	"github.com/brave-experiments/accounts/datastore"
	"github.com/brave-experiments/accounts/middleware"
	"github.com/brave-experiments/accounts/util"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/render"
	"github.com/google/uuid"
)

type SessionsController struct {
	datastore *datastore.Datastore
}

func NewSessionsController(datastore *datastore.Datastore) *SessionsController {
	return &SessionsController{
		datastore: datastore,
	}
}

// @Summary List sessions
// @Description Lists all active sessions for the authenticated account
// @Tags Sessions
// @Produce json
// @Param Authorization header string true "Bearer + auth token"
// @Success 200 {array} datastore.Session
// @Failure 401 {object} util.ErrorResponse
// @Failure 500 {object} util.ErrorResponse
// @Router /v2/sessions [get]
func (sc *SessionsController) ListSessions(w http.ResponseWriter, r *http.Request) {
	session := r.Context().Value(middleware.ContextSession).(*datastore.Session)

	sessions, err := sc.datastore.ListSessions(session.AccountID)
	if err != nil {
		util.RenderErrorResponse(w, r, http.StatusInternalServerError, err)
		return
	}

	render.Status(r, http.StatusOK)
	render.JSON(w, r, sessions)
}

// @Summary Delete session / log out
// @Description Deletes a specific session by ID
// @Tags Sessions
// @Param Authorization header string true "Bearer + auth token"
// @Param id path string true "Session ID (UUID)"
// @Success 204 "No Content"
// @Failure 400 {object} util.ErrorResponse
// @Failure 401 {object} util.ErrorResponse
// @Failure 404 {object} util.ErrorResponse
// @Failure 500 {object} util.ErrorResponse
// @Router /v2/sessions/{id} [delete]
func (sc *SessionsController) DeleteSession(w http.ResponseWriter, r *http.Request) {
	sessionID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		util.RenderErrorResponse(w, r, http.StatusBadRequest, err)
		return
	}

	currentSession := r.Context().Value("session").(*datastore.Session)

	if err := sc.datastore.DeleteSession(sessionID, currentSession.AccountID); err != nil {
		if errors.Is(err, datastore.ErrSessionNotFound) {
			util.RenderErrorResponse(w, r, http.StatusNotFound, err)
			return
		}
		util.RenderErrorResponse(w, r, http.StatusInternalServerError, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (sc *SessionsController) Router(authMiddleware func(http.Handler) http.Handler) chi.Router {
	r := chi.NewRouter()
	r.Use(authMiddleware)

	r.Get("/", sc.ListSessions)
	r.Delete("/{id}", sc.DeleteSession)

	return r
}
