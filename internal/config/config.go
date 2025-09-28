package config

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

	"github.com/matheuscscp/mcp-oauth2-proxy/internal/constants"
)

const (
	MaxGroups = 100

	defaultServerAddr   = ":8080"
	scopesCacheDuration = 10 * time.Second
)

type Config struct {
	Provider ProviderConfig `yaml:"provider" json:"provider"`
	Proxy    ProxyConfig    `yaml:"proxy" json:"proxy"`
	Server   ServerConfig   `yaml:"server" json:"server"`
}

type ProviderConfig struct {
	Name                string   `yaml:"name" json:"name"`
	ClientID            string   `yaml:"clientID" json:"clientID"`
	ClientSecret        string   `yaml:"clientSecret" json:"clientSecret"`
	Organization        string   `yaml:"organization" json:"organization"`
	AllowedEmailDomains []string `yaml:"allowedEmailDomains" json:"allowedEmailDomains"`

	regexAllowedEmailDomains []*regexp.Regexp
}

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

type ServerConfig struct {
	Addr string `yaml:"addr" json:"addr"`
}

func Load() (*Config, error) {
	fileName := "/etc/mcp-oauth2-proxy/config/config.yaml"
	if fn := os.Getenv("MCP_OAUTH2_PROXY_CONFIG"); fn != "" {
		fileName = fn
	}
	var cfg Config
	f, err := os.Open(fileName)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if err := yaml.NewDecoder(f).Decode(&cfg); err != nil {
		return nil, err
	}
	if err := cfg.ValidateAndInitialize(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func (c *Config) ValidateAndInitialize() error {
	// Apply defaults.
	if c.Provider.AllowedEmailDomains == nil {
		c.Provider.AllowedEmailDomains = []string{}
	}
	if c.Proxy.Hosts == nil {
		c.Proxy.Hosts = []*HostConfig{}
	}
	if c.Proxy.AllowedRedirectURLs == nil {
		c.Proxy.AllowedRedirectURLs = []string{}
	}
	if c.Server.Addr == "" {
		c.Server.Addr = defaultServerAddr
	}

	// Validate required fields.
	if c.Provider.Name == "" {
		return fmt.Errorf("provider.name must be set")
	}
	if c.Provider.ClientID == "" {
		return fmt.Errorf("provider.clientID must be set")
	}
	if c.Provider.ClientSecret == "" {
		return fmt.Errorf("provider.clientSecret must be set")
	}
	for i, h := range c.Proxy.Hosts {
		if h.Host == "" {
			return fmt.Errorf("host is empty for proxy.hosts[%d]", i)
		}
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

func GetEmailDomain(email string) string {
	s := strings.Split(email, "@")
	if len(s) == 2 {
		return s[1]
	}
	return ""
}

func (p *ProviderConfig) ValidateEmailDomain(email string) bool {
	domain := GetEmailDomain(email)
	if domain == "" {
		return false
	}
	if len(p.regexAllowedEmailDomains) == 0 {
		return true
	}
	for _, r := range p.regexAllowedEmailDomains {
		if r.MatchString(domain) {
			return true
		}
	}
	return false
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
