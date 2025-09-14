package main

import (
	_ "embed"
	"encoding/json"
	"net/http"
	"slices"
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
	coveredByMapToSet := make(map[string]map[string]struct{})
	for _, s := range scopes {
		for _, c := range s.Covers {
			if _, ok := coveredByMapToSet[c]; !ok {
				coveredByMapToSet[c] = make(map[string]struct{})
			}
			coveredByMapToSet[c][s.Name] = struct{}{}
		}
	}
	coveredByMap := make(map[string][]string, len(coveredByMapToSet))
	for k, v := range coveredByMapToSet {
		for name := range v {
			coveredByMap[k] = append(coveredByMap[k], name)
		}
		slices.Sort(coveredByMap[k])
	}
	scopesForWebpage := make([]scopeConfigForWebpage, len(scopes))
	for i, s := range scopes {
		coveredBy := coveredByMap[s.Name]
		if len(coveredBy) == 0 {
			coveredBy = []string{}
		}
		scopesForWebpage[i] = scopeConfigForWebpage{
			Name:        s.Name,
			Description: s.Description,
			CoveredBy:   coveredBy,
		}
	}
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
