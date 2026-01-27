package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"slices"
	"sync"
	"time"
)

const PORT = "4566"

type EmailHeader struct {
	Name  string
	Value string
}

type EmailContent struct {
	Simple struct {
		Body struct {
			Html struct {
				Data string
			}
			Text struct {
				Data string
			}
		}
		Subject struct {
			Data string
		}
		Headers []EmailHeader
	}
}

type EmailDestination struct {
	ToAddresses []string
}

type SendEmailRequest struct {
	Content          EmailContent
	Destination      EmailDestination
	FromEmailAddress string
	Timestamp        time.Time
}

type SendEmailResponse struct {
	MessageId string
}

type MessagesResponse struct {
	Messages []SendEmailRequest `json:"messages"`
}

type EmailStore struct {
	mu       sync.RWMutex
	messages []SendEmailRequest
}

func (s *EmailStore) Add(email SendEmailRequest) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.messages = append(s.messages, email)
}

func (s *EmailStore) GetAll() []SendEmailRequest {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return slices.Clone(s.messages)
}

func (s *EmailStore) Clear() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.messages = []SendEmailRequest{}
}

var store = &EmailStore{
	messages: []SendEmailRequest{},
}

func generateMessageId() string {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		panic(fmt.Sprintf("failed to generate message ID: %v", err))
	}
	return hex.EncodeToString(bytes)
}

type ErrorResponse struct {
	Message string `json:"message"`
}

func writeJSON(w http.ResponseWriter, statusCode int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		log.Printf("failed to encode JSON response: %v", err)
	}
}

func writeError(w http.ResponseWriter, statusCode int, message string) {
	writeJSON(w, statusCode, ErrorResponse{Message: message})
}

func sendEmailHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	var req SendEmailRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("Invalid request body: %v", err))
		return
	}

	if req.FromEmailAddress == "" {
		writeError(w, http.StatusBadRequest, "FromEmailAddress is required")
		return
	}

	if len(req.Destination.ToAddresses) == 0 {
		writeError(w, http.StatusBadRequest, "At least one ToAddress is required")
		return
	}

	if req.Content.Simple.Subject.Data == "" {
		writeError(w, http.StatusBadRequest, "Subject is required")
		return
	}

	if req.Content.Simple.Body.Html.Data == "" && req.Content.Simple.Body.Text.Data == "" {
		writeError(w, http.StatusBadRequest, "Either HTML or Text body is required")
		return
	}

	req.Timestamp = time.Now()
	messageId := generateMessageId()

	store.Add(req)

	log.Printf("Email sent: MessageId=%s, To=%v, From=%s, Subject=%s",
		messageId, req.Destination.ToAddresses, req.FromEmailAddress, req.Content.Simple.Subject.Data)

	resp := SendEmailResponse{
		MessageId: messageId,
	}

	writeJSON(w, http.StatusOK, resp)
}

func getMessagesHandler(w http.ResponseWriter) {
	messages := store.GetAll()
	resp := MessagesResponse{
		Messages: messages,
	}

	writeJSON(w, http.StatusOK, resp)
}

func deleteMessagesHandler(w http.ResponseWriter) {
	store.Clear()
	log.Println("All messages cleared")

	w.WriteHeader(http.StatusNoContent)
}

func main() {
	http.HandleFunc("/v2/email/outbound-emails", sendEmailHandler)
	http.HandleFunc("/_aws/ses", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			getMessagesHandler(w)
		case http.MethodDelete:
			deleteMessagesHandler(w)
		default:
			writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		}
	})

	log.Printf("Starting SES v2 mock server on port %s", PORT)

	if err := http.ListenAndServe(":"+PORT, nil); err != nil {
		log.Fatal(err)
	}
}
