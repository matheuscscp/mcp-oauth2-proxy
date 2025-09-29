package config

import (
	"regexp"
	"strings"
)

const (
	MaxGroups = 100
)

type ProviderConfig struct {
	Name                string   `yaml:"name" json:"name"`
	ClientID            string   `yaml:"clientID" json:"clientID"`
	ClientSecret        string   `yaml:"clientSecret" json:"clientSecret"`
	Organization        string   `yaml:"organization" json:"organization"`
	AllowedEmailDomains []string `yaml:"allowedEmailDomains" json:"allowedEmailDomains"`

	regexAllowedEmailDomains []*regexp.Regexp
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

func GetEmailDomain(email string) string {
	s := strings.Split(email, "@")
	if len(s) == 2 {
		return s[1]
	}
	return ""
}
