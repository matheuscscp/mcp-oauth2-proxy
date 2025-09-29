package server

import (
	"fmt"
	"net/http"

	"github.com/matheuscscp/mcp-oauth2-proxy/internal/config"
)

const (
	stateCookieName = "csrf-state"
)

func setState(w http.ResponseWriter, state string) {
	c := &http.Cookie{
		Name:     stateCookieName,
		Value:    state,
		Path:     pathCallback,
		MaxAge:   int(config.TransactionTimeout.Seconds()),
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	}
	http.SetCookie(w, c)
}

func getAndDeleteStateAndCheckCSRF(w http.ResponseWriter, r *http.Request) (string, error) {
	// Get state.
	c, err := r.Cookie(stateCookieName)
	if err != nil {
		return "", fmt.Errorf("expired")
	}

	// Delete state.
	http.SetCookie(w, &http.Cookie{
		Name:   stateCookieName,
		Path:   pathCallback,
		MaxAge: -1,
	})

	// Check CSRF token.
	cookieState := c.Value
	queryState := state(r)
	if cookieState != queryState {
		return "", fmt.Errorf("mismatch")
	}

	return cookieState, nil
}
