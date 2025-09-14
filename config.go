package main

import (
	"fmt"
	"os"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

const (
	defaultServerAddr = ":8080"
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
	AllowedRedirectURLs []string     `yaml:"allowedRedirectURLs" json:"allowedRedirectURLs"`
	Hosts               []hostConfig `yaml:"hosts" json:"hosts"`

	regexAllowedRedirectURLs []*regexp.Regexp
}

type hostConfig struct {
	Host   string        `yaml:"host" json:"host"`
	Scopes []scopeConfig `yaml:"scopes" json:"scopes"`
}

type scopeConfig struct {
	Name        string   `yaml:"name" json:"name"`
	Description string   `yaml:"description" json:"description"`
	Covers      []string `yaml:"covers" json:"covers"`
}

type serverConfig struct {
	Addr string `yaml:"addr" json:"addr"`
	CORS bool   `yaml:"cors" json:"cors"`
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
	if c.Proxy.AllowedRedirectURLs == nil {
		c.Proxy.AllowedRedirectURLs = []string{}
	}
	if c.Proxy.Hosts == nil {
		c.Proxy.Hosts = []hostConfig{}
	}
	for i := range c.Proxy.Hosts {
		if c.Proxy.Hosts[i].Scopes == nil {
			c.Proxy.Hosts[i].Scopes = []scopeConfig{}
		}
		for j := range c.Proxy.Hosts[i].Scopes {
			if c.Proxy.Hosts[i].Scopes[j].Covers == nil {
				c.Proxy.Hosts[i].Scopes[j].Covers = []string{}
			}
		}
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

func (p *proxyConfig) supportedScopes(host string) ([]string, []scopeConfig) {
	for _, h := range p.Hosts {
		if h.Host == host {
			if len(h.Scopes) == 0 {
				return []string{authorizationServerDefaultScope}, nil
			}
			scopes := make([]string, 0, len(h.Scopes))
			for _, s := range h.Scopes {
				scopes = append(scopes, s.Name)
			}
			return scopes, h.Scopes
		}
	}
	return []string{authorizationServerDefaultScope}, nil
}
