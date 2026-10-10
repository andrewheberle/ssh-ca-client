package api

import (
	"encoding/json"
	"fmt"
	"strings"
)

// StatusError returns an error for a response with an unexpected status code,
// including any error messages from the CA in body.
func StatusError(statusCode int, body []byte) error {
	if messages := errorMessages(body); messages != "" {
		return fmt.Errorf("bad status code: %d: %s", statusCode, messages)
	}

	return fmt.Errorf("bad status code: %d", statusCode)
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
