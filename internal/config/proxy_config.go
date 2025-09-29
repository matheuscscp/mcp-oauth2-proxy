package config

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"sync"
	"time"

	"github.com/mark3labs/mcp-go/client"
	"github.com/mark3labs/mcp-go/mcp"

	"github.com/matheuscscp/mcp-oauth2-proxy/internal/constants"
)

const (
	TransactionTimeout = time.Minute

	scopesCacheDuration = 10 * time.Second
)

type ProxyConfig struct {
	Hosts                []*HostConfig `yaml:"hosts" json:"hosts"`
	DisableConsentScreen bool          `yaml:"disableConsentScreen" json:"disableConsentScreen"`
	AllowedRedirectURLs  []string      `yaml:"allowedRedirectURLs" json:"allowedRedirectURLs"`
	CORS                 bool          `yaml:"cors" json:"cors"`

	regexAllowedRedirectURLs []*regexp.Regexp
}

type HostConfig struct {
	Host     string `yaml:"host" json:"host"`
	Endpoint string `yaml:"endpoint" json:"endpoint"`

	scopes         []ScopeConfig
	scopesDeadline time.Time
	scopesMu       sync.Mutex
}

type ScopeConfig struct {
	Name        string   `yaml:"name" json:"name"`
	Description string   `yaml:"description" json:"description"`
	Tools       []string `yaml:"tools" json:"tools"`
}

func (p *ProxyConfig) AcceptsHost(host string) bool {
	for _, h := range p.Hosts {
		if h.Host == host {
			return true
		}
	}
	return false
}

func (p *ProxyConfig) ValidateRedirectURL(url string) bool {
	if url == "" {
		return false
	}
	if len(p.regexAllowedRedirectURLs) == 0 {
		return true
	}
	for _, r := range p.regexAllowedRedirectURLs {
		if r.MatchString(url) {
			return true
		}
	}
	return false
}

func (p *ProxyConfig) SupportedScopes(ctx context.Context, host string) ([]string, []ScopeConfig, error) {
	now := time.Now()
	for _, h := range p.Hosts {
		if h.Host != host {
			continue
		}
		scopes, err := p.getSupportedScopes(ctx, h, now)
		if err != nil {
			return nil, nil, err
		}
		if len(scopes) == 0 {
			return []string{constants.AuthorizationServerDefaultScope}, nil, nil
		}
		scopeNames := make([]string, 0, len(scopes))
		for _, s := range scopes {
			scopeNames = append(scopeNames, s.Name)
		}
		return scopeNames, scopes, nil
	}
	return []string{constants.AuthorizationServerDefaultScope}, nil, nil
}

func (p *ProxyConfig) getSupportedScopes(ctx context.Context, h *HostConfig, now time.Time) ([]ScopeConfig, error) {
	ep := h.Endpoint
	if ep == "" {
		return nil, nil
	}

	h.scopesMu.Lock()
	defer h.scopesMu.Unlock()

	scopes := h.scopes
	if !now.Before(h.scopesDeadline) {
		var err error
		scopes, err = p.fetchSupportedScopes(ctx, ep)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch supported scopes from '%s': %w", ep, err)
		}
		h.scopes = scopes
		h.scopesDeadline = now.Add(scopesCacheDuration)
	}

	return scopes, nil
}

func (p *ProxyConfig) fetchSupportedScopes(ctx context.Context, endpoint string) ([]ScopeConfig, error) {
	c, err := client.NewStreamableHttpClient(endpoint)
	if err != nil {
		return nil, fmt.Errorf("failed to create MCP client: %w", err)
	}
	defer c.Close()
	_, err = c.Initialize(ctx, mcp.InitializeRequest{})
	if err != nil {
		return nil, fmt.Errorf("failed to initialize MCP client: %w", err)
	}
	resp, err := c.ListTools(ctx, mcp.ListToolsRequest{})
	if err != nil {
		return nil, fmt.Errorf("failed to list MCP tools: %w", err)
	}
	b, err := json.Marshal(resp.Meta.AdditionalFields)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal MCP tools: %w", err)
	}
	var payload struct {
		Scopes []ScopeConfig `json:"scopes"`
	}
	if err := json.Unmarshal(b, &payload); err != nil {
		return nil, fmt.Errorf("failed to unmarshal MCP tools: %w", err)
	}
	return payload.Scopes, nil
}
