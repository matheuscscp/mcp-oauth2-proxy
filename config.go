package main

import (
	"os"

	"gopkg.in/yaml.v3"
)

type config struct {
	Provider providerConfig `yaml:"provider"`
	Server   serverConfig   `yaml:"server"`
}

type providerConfig struct {
	Name                string   `yaml:"name"`
	ClientID            string   `yaml:"clientID"`
	ClientSecret        string   `yaml:"clientSecret"`
	AllowedEmailDomains []string `yaml:"allowedEmailDomains"`
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
