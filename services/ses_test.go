package services

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type failingWriter struct{}

func (f failingWriter) Write(p []byte) (int, error) {
	return 0, errors.New("write failed")
}

func TestBuildRawEmail(t *testing.T) {
	to := "user@example.com"
	subject := "Test Subject"
	textContent := "Hello, this is plain text."
	htmlContent := "<html><body>Hello, this is HTML.</body></html>"

	t.Run("builds valid email structure", func(t *testing.T) {
		raw, err := buildRawEmail(to, subject, textContent, htmlContent, nil)
		require.NoError(t, err)
		email := string(raw)

		// Check headers in correct order
		toIdx := strings.Index(email, "To: ")
		subjectIdx := strings.Index(email, "Subject: ")
		mimeIdx := strings.Index(email, "MIME-Version: ")
		contentTypeIdx := strings.Index(email, "Content-Type: multipart/alternative")

		assert.True(t, toIdx < subjectIdx, "To should come before Subject")
		assert.True(t, subjectIdx < mimeIdx, "Subject should come before MIME-Version")
		assert.True(t, mimeIdx < contentTypeIdx, "MIME-Version should come before Content-Type")
	})

	t.Run("includes correct header values", func(t *testing.T) {
		raw, err := buildRawEmail(to, subject, textContent, htmlContent, nil)
		require.NoError(t, err)
		email := string(raw)

		assert.Contains(t, email, "To: user@example.com\r\n")
		assert.Contains(t, email, "Subject: Test Subject\r\n")
		assert.Contains(t, email, "MIME-Version: 1.0\r\n")
		assert.NotContains(t, email, "From:")
	})

	t.Run("includes both text and HTML parts", func(t *testing.T) {
		raw, err := buildRawEmail(to, subject, textContent, htmlContent, nil)
		require.NoError(t, err)
		email := string(raw)

		assert.Contains(t, email, "Content-Type: text/plain; charset=UTF-8")
		assert.Contains(t, email, "Content-Type: text/html; charset=UTF-8")
		assert.Contains(t, email, textContent)
		assert.Contains(t, email, htmlContent)
	})

	t.Run("includes custom headers", func(t *testing.T) {
		headers := map[string]string{
			"Custom-Header": "custom-value",
			"X-Another":     "another-value",
		}
		raw, err := buildRawEmail(to, subject, textContent, htmlContent, headers)
		require.NoError(t, err)
		email := string(raw)

		assert.Contains(t, email, "Custom-Header: custom-value\r\n")
		assert.Contains(t, email, "X-Another: another-value\r\n")
	})

	t.Run("Q-encodes non-ASCII custom header values", func(t *testing.T) {
		headers := map[string]string{
			"X-Mas": "noël",
		}
		raw, err := buildRawEmail(to, subject, textContent, htmlContent, headers)
		require.NoError(t, err)
		email := string(raw)

		assert.Contains(t, email, "X-Mas: =?UTF-8?q?")
		assert.NotContains(t, email, "X-Mas: noël")
	})

	t.Run("does not Q-encode ASCII-only custom header values", func(t *testing.T) {
		headers := map[string]string{
			"X-Custom": "plain-ascii-value",
		}
		raw, err := buildRawEmail(to, subject, textContent, htmlContent, headers)
		require.NoError(t, err)
		email := string(raw)

		assert.Contains(t, email, "X-Custom: plain-ascii-value\r\n")
	})

	t.Run("Q-encodes non-ASCII subject", func(t *testing.T) {
		nonAsciiSubject := "Vérifiez votre adresse de courriel"
		raw, err := buildRawEmail(to, nonAsciiSubject, textContent, htmlContent, nil)
		require.NoError(t, err)
		email := string(raw)

		assert.Contains(t, email, "=?UTF-8?q?") // stdlib uses lowercase q
		assert.NotContains(t, email, "Subject: Vérifiez")
	})

	t.Run("does not Q-encode ASCII-only subject", func(t *testing.T) {
		raw, err := buildRawEmail(to, subject, textContent, htmlContent, nil)
		require.NoError(t, err)
		email := string(raw)

		assert.Contains(t, email, "Subject: Test Subject\r\n")
		assert.NotContains(t, email, "=?UTF-8?q?")
	})

	t.Run("boundary format matches expected pattern", func(t *testing.T) {
		raw, err := buildRawEmail(to, subject, textContent, htmlContent, nil)
		require.NoError(t, err)
		email := string(raw)

		assert.Contains(t, email, "boundary=\"----=_Part_")
	})

	t.Run("email ends with closing boundary", func(t *testing.T) {
		raw, err := buildRawEmail(to, subject, textContent, htmlContent, nil)
		require.NoError(t, err)
		email := string(raw)

		assert.True(t, strings.HasSuffix(email, "--\r\n"))
	})
}

func TestQuotePrint(t *testing.T) {
	t.Run("writes ASCII content", func(t *testing.T) {
		var buf bytes.Buffer
		err := quotePrint(&buf, "Hello, World!")
		require.NoError(t, err)
		assert.Equal(t, "Hello, World!", buf.String())
	})

	t.Run("encodes non-ASCII characters", func(t *testing.T) {
		var buf bytes.Buffer
		err := quotePrint(&buf, "François")
		require.NoError(t, err)
		assert.Equal(t, "Fran=C3=A7ois", buf.String())
	})

	t.Run("handles empty content", func(t *testing.T) {
		var buf bytes.Buffer
		err := quotePrint(&buf, "")
		require.NoError(t, err)
		assert.Equal(t, "", buf.String())
	})

	t.Run("returns error on write failure", func(t *testing.T) {
		err := quotePrint(failingWriter{}, "test")
		require.Error(t, err)
		assert.Equal(t, "write failed", err.Error())
	})
}
