package main

import (
	"fmt"
	"os"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

type config struct {
	Provider providerConfig `yaml:"provider"`
	Proxy    proxyConfig    `yaml:"proxy"`
	Server   serverConfig   `yaml:"server"`
}

type providerConfig struct {
	Name                string   `yaml:"name"`
	ClientID            string   `yaml:"clientID"`
	ClientSecret        string   `yaml:"clientSecret"`
	AllowedEmailDomains []string `yaml:"allowedEmailDomains"`

	regexAllowedEmailDomains []*regexp.Regexp
}

type proxyConfig struct {
	AllowedRedirectURLs []string `yaml:"allowedRedirectURLs"`

	regexAllowedRedirectURLs []*regexp.Regexp
}

type serverConfig struct {
	Addr string `yaml:"addr"`
	CORS bool   `yaml:"cors"`
}

func readConfig() (*config, error) {
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
	return &cfg, nil
}

func newConfig() (*config, error) {
	c, err := readConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to read config: %w", err)
	}

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
		return nil, fmt.Errorf("failed to build regex list for allowed email domains: %w", err)
	}

	if err := buildRegexList(c.Proxy.AllowedRedirectURLs, &c.Proxy.regexAllowedRedirectURLs); err != nil {
		return nil, fmt.Errorf("failed to build regex list for allowed redirect URLs: %w", err)
	}

	return c, nil
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
