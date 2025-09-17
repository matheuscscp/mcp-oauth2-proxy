package main

import (
	_ "embed"
	"encoding/json"
	"net/http"
	"strings"
)

//go:embed scopes.html
var scopeSelectionPage string

func respondScopeSelectionPage(w http.ResponseWriter, r *http.Request, scopes []scopeConfig) {
	// Prepare scopes for webpage.
	type scopeConfigForWebpage struct {
		Name        string   `json:"name"`
		Description string   `json:"description"`
		CoveredBy   []string `json:"coveredBy"`
	}
	toolsCoveredByScope := make(map[string]map[string]struct{})
	for _, s := range scopes {
		toolsCovered := make(map[string]struct{})
		for _, t := range s.Tools {
			toolsCovered[t] = struct{}{}
		}
		toolsCoveredByScope[s.Name] = toolsCovered
	}
	scopesForWebpage := make([]scopeConfigForWebpage, 0, len(scopes))
	for i, a := range scopes {
		scope := scopeConfigForWebpage{
			Name:        a.Name,
			Description: a.Description,
		}
		for j, b := range scopes {
			if i == j {
				continue
			}
			aCoveredByB := true
			for toolCoveredByA := range toolsCoveredByScope[a.Name] {
				if _, ok := toolsCoveredByScope[b.Name][toolCoveredByA]; !ok {
					aCoveredByB = false
					break
				}
			}
			if aCoveredByB {
				scope.CoveredBy = append(scope.CoveredBy, b.Name)
			}
		}
		scopesForWebpage = append(scopesForWebpage, scope)
	}

	// Marshal scopes for webpage.
	b, err := json.Marshal(scopesForWebpage)
	if err != nil {
		fromRequest(r).WithError(err).Error("failed to marshal scopes for webpage")
		http.Error(w, "Failed to marshal scopes", http.StatusInternalServerError)
		return
	}
	scopesJSON := string(b)

	// Render page.
	page := strings.ReplaceAll(scopeSelectionPage, "MCP_HOST", r.Host)
	page = strings.ReplaceAll(page, "MCP_SCOPES", scopesJSON)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if _, err := w.Write([]byte(page)); err != nil {
		fromRequest(r).WithError(err).Error("failed to write scope selection page")
	}
}
