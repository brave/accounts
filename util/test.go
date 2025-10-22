package util

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func ExecuteTestRequest(req *http.Request, handler http.Handler) *httptest.ResponseRecorder {
	rr := httptest.NewRecorder()
	req.RemoteAddr = "127.0.0.1:12345"
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

func AssertErrorResponseCode(t *testing.T, resp *httptest.ResponseRecorder, expectedCode int) {
	var errResp ErrorResponse
	DecodeJSONTestResponse(t, resp.Body, &errResp)
	require.NotNil(t, errResp.Code)
	assert.Equal(t, expectedCode, *errResp.Code)
}
