package util

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func ExecuteTestRequest(req *http.Request, handler http.Handler) *httptest.ResponseRecorder {
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	return rr
}

func CreateJSONTestRequest(path string, body interface{}) *http.Request {
	bodyJSON, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewBuffer(bodyJSON))
	req.Header.Set("Content-Type", "application/json")
	return req
}

func DecodeJSONTestResponse(t *testing.T, body *bytes.Buffer, parsed interface{}) {
	err := json.NewDecoder(body).Decode(parsed)
	assert.NoError(t, err)
}
