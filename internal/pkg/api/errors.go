package api

import (
	"encoding/json"
	"fmt"
	"strings"
	"unicode/utf8"
)

// maxMessageLength is the most bytes of the CA's error messages kept in an
// error, so a misbehaving CA can't fill the logs
const maxMessageLength = 512

// StatusError returns an error for a response with an unexpected status code,
// including any error messages from the CA in body, cut to
// [maxMessageLength] bytes.
func StatusError(statusCode int, body []byte) error {
	if messages := truncate(errorMessages(body), maxMessageLength); messages != "" {
		return fmt.Errorf("bad status code: %d: %s", statusCode, messages)
	}

	return fmt.Errorf("bad status code: %d", statusCode)
}

// truncate returns s cut to at most max bytes, at a UTF-8 character boundary,
// with "..." added if it was cut
func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}

	cut := max
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}

	return s[:cut] + "..."
}

// errorMessages returns the error messages from an error response body
// returned by the CA, joined with "; ". It returns an empty string if body is
// not an error response or contains no messages.
func errorMessages(body []byte) string {
	var res struct {
		Errors []struct {
			Message string `json:"message"`
		} `json:"errors"`
	}
	if err := json.Unmarshal(body, &res); err != nil {
		return ""
	}

	messages := make([]string, 0, len(res.Errors))
	for _, e := range res.Errors {
		if e.Message != "" {
			messages = append(messages, e.Message)
		}
	}

	return strings.Join(messages, "; ")
}
