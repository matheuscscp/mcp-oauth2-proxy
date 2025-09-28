package server

import (
	"testing"

	. "github.com/onsi/gomega"

	"github.com/matheuscscp/mcp-oauth2-proxy/internal/config"
)

func TestNew(t *testing.T) {
	g := NewWithT(t)
	s := New(&config.Config{}, nil)
	g.Expect(s).NotTo(BeNil())
}
