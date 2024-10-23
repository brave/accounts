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
