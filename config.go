package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/mark3labs/mcp-go/client"
	"github.com/mark3labs/mcp-go/mcp"
	"gopkg.in/yaml.v3"
)

const (
	defaultServerAddr   = ":8080"
	scopesCacheDuration = 10 * time.Second
)

type config struct {
	Provider providerConfig `yaml:"provider" json:"provider"`
	Proxy    proxyConfig    `yaml:"proxy" json:"proxy"`
	Server   serverConfig   `yaml:"server" json:"server"`
}

type providerConfig struct {
	Name                string   `yaml:"name" json:"name"`
	ClientID            string   `yaml:"clientID" json:"clientID"`
	ClientSecret        string   `yaml:"clientSecret" json:"clientSecret"`
	AllowedEmailDomains []string `yaml:"allowedEmailDomains" json:"allowedEmailDomains"`

	regexAllowedEmailDomains []*regexp.Regexp
}

type proxyConfig struct {
	Hosts               []*hostConfig `yaml:"hosts" json:"hosts"`
	AllowedRedirectURLs []string      `yaml:"allowedRedirectURLs" json:"allowedRedirectURLs"`
	CORS                bool          `yaml:"cors" json:"cors"`

	regexAllowedRedirectURLs []*regexp.Regexp
}

type hostConfig struct {
	Host     string `yaml:"host" json:"host"`
	Endpoint string `yaml:"endpoint" json:"endpoint"`

	scopes         []scopeConfig
	scopesDeadline time.Time
	scopesMu       sync.Mutex
}

type scopeConfig struct {
	Name        string   `yaml:"name" json:"name"`
	Description string   `yaml:"description" json:"description"`
	Tools       []string `yaml:"tools" json:"tools"`
}

type serverConfig struct {
	Addr string `yaml:"addr" json:"addr"`
}

func newConfig() (*config, error) {
	fileName := "/etc/mcp-oauth2-proxy/config/config.yaml"
	if fn := os.Getenv("MCP_OAUTH2_PROXY_CONFIG"); fn != "" {
		fileName = fn
	}
	var cfg config
	f, err := os.Open(fileName)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if err := yaml.NewDecoder(f).Decode(&cfg); err != nil {
		return nil, err
	}
	if err := cfg.validateAndInitialize(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func (c *config) validateAndInitialize() error {
	// Apply defaults.
	if c.Provider.Name == "" {
		c.Provider.Name = providerGoogle
	}
	if c.Provider.AllowedEmailDomains == nil {
		c.Provider.AllowedEmailDomains = []string{}
	}
	if c.Proxy.Hosts == nil {
		c.Proxy.Hosts = []*hostConfig{}
	}
	for _, h := range c.Proxy.Hosts {
		if h.Host == "" || h.Endpoint == "" {
			return fmt.Errorf("both host and endpoint must be set for each proxy host")
		}
	}
	if c.Proxy.AllowedRedirectURLs == nil {
		c.Proxy.AllowedRedirectURLs = []string{}
	}
	if c.Server.Addr == "" {
		c.Server.Addr = defaultServerAddr
	}

	// Validate client credentials.
	if c.Provider.ClientID == "" {
		return fmt.Errorf("provider.clientID must be set")
	}
	if c.Provider.ClientSecret == "" {
		return fmt.Errorf("provider.clientSecret must be set")
	}

	// Compile regular expressions.
	buildRegexList := func(in []string, out *[]*regexp.Regexp) error {
		for _, s := range in {
			r, err := regexp.Compile(s)
			if err != nil {
				return fmt.Errorf("failed to compile regex '%s': %w", s, err)
			}
			*out = append(*out, r)
		}
		return nil
	}
	if err := buildRegexList(c.Provider.AllowedEmailDomains, &c.Provider.regexAllowedEmailDomains); err != nil {
		return fmt.Errorf("failed to build regex list for allowed email domains: %w", err)
	}
	if err := buildRegexList(c.Proxy.AllowedRedirectURLs, &c.Proxy.regexAllowedRedirectURLs); err != nil {
		return fmt.Errorf("failed to build regex list for allowed redirect URLs: %w", err)
	}

	return nil
}

func (p *providerConfig) validateEmailDomain(email string) bool {
	if len(p.regexAllowedEmailDomains) == 0 {
		return true
	}
	s := strings.Split(email, "@")
	if len(s) != 2 {
		return false
	}
	domain := s[1]
	for _, r := range p.regexAllowedEmailDomains {
		if r.MatchString(domain) {
			return true
		}
	}
	return false
}

func (p *proxyConfig) validateRedirectURL(url string) bool {
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

func (p *proxyConfig) supportedScopes(ctx context.Context, host string, now time.Time) ([]string, []scopeConfig, error) {
	for _, h := range p.Hosts {
		if h.Host != host {
			continue
		}
		scopes, err := p.getSupportedScopes(ctx, h, now)
		if err != nil {
			return nil, nil, err
		}
		if len(scopes) == 0 {
			return []string{authorizationServerDefaultScope}, nil, nil
		}
		scopeNames := make([]string, 0, len(scopes))
		for _, s := range scopes {
			scopeNames = append(scopeNames, s.Name)
		}
		return scopeNames, scopes, nil
	}
	return []string{authorizationServerDefaultScope}, nil, nil
}

func (p *proxyConfig) getSupportedScopes(ctx context.Context, h *hostConfig, now time.Time) ([]scopeConfig, error) {
	h.scopesMu.Lock()
	defer h.scopesMu.Unlock()

	scopes := h.scopes
	if !now.Before(h.scopesDeadline) {
		var err error
		scopes, err = p.fetchSupportedScopes(ctx, h.Endpoint)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch supported scopes from '%s': %w", h.Endpoint, err)
		}
		h.scopes = scopes
		h.scopesDeadline = now.Add(scopesCacheDuration)
	}

	return scopes, nil
}

func (p *proxyConfig) fetchSupportedScopes(ctx context.Context, endpoint string) ([]scopeConfig, error) {
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
		Scopes []scopeConfig `json:"scopes"`
	}
	if err := json.Unmarshal(b, &payload); err != nil {
		return nil, fmt.Errorf("failed to unmarshal MCP tools: %w", err)
	}
	return payload.Scopes, nil
}
