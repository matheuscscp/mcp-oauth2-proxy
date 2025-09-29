package config

import (
	"fmt"
	"os"
	"regexp"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Provider ProviderConfig `yaml:"provider" json:"provider"`
	Proxy    ProxyConfig    `yaml:"proxy" json:"proxy"`
	Server   ServerConfig   `yaml:"server" json:"server"`
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
