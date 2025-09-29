package config

const (
	defaultServerAddr = ":8080"
)

type ServerConfig struct {
	Addr string `yaml:"addr" json:"addr"`
}
