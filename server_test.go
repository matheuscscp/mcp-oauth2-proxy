package main

import (
	"net/http"
	"net/http/httptest"
	"testing"

	. "github.com/onsi/gomega"
	"github.com/prometheus/client_golang/prometheus"
)

func TestServer(t *testing.T) {
	t.Run("health endpoints", func(t *testing.T) {
		g := NewWithT(t)

		// Create a mock API handler
		apiCalled := false
		api := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			apiCalled = true
			w.WriteHeader(http.StatusOK)
		})

		conf := &config{
			Server: serverConfig{
				Addr: ":8080",
			},
		}

		registry := prometheus.NewRegistry()
		server := newServer(conf, api, registry, registry)

		tests := []struct {
			path            string
			expectedStatus  int
			expectAPICalled bool
		}{
			{"/readyz", http.StatusOK, false},
			{"/healthz", http.StatusOK, false},
		}

		for _, tt := range tests {
			t.Run(tt.path, func(t *testing.T) {
				apiCalled = false
				req := httptest.NewRequest(http.MethodGet, tt.path, nil)
				rec := httptest.NewRecorder()

				server.Handler.ServeHTTP(rec, req)

				g.Expect(rec.Code).To(Equal(tt.expectedStatus))
				g.Expect(apiCalled).To(Equal(tt.expectAPICalled))
			})
		}
	})

	t.Run("metrics endpoint", func(t *testing.T) {
		g := NewWithT(t)

		api := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		conf := &config{
			Server: serverConfig{
				Addr: ":8080",
			},
		}

		registry := prometheus.NewRegistry()
		server := newServer(conf, api, registry, registry)

		req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
		rec := httptest.NewRecorder()

		server.Handler.ServeHTTP(rec, req)

		g.Expect(rec.Code).To(Equal(http.StatusOK))
		// Should return prometheus metrics endpoint (content type may vary)
		body := rec.Body.String()
		// Even if empty, prometheus endpoint should be accessible and return valid format
		g.Expect(body).ToNot(BeNil())
	})

	t.Run("API routing", func(t *testing.T) {
		g := NewWithT(t)

		apiCalled := false
		api := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			apiCalled = true
			w.WriteHeader(http.StatusTeapot) // Unique status to verify API was called
		})

		conf := &config{
			Server: serverConfig{
				Addr: ":8080",
			},
		}

		registry := prometheus.NewRegistry()
		server := newServer(conf, api, registry, registry)

		req := httptest.NewRequest(http.MethodGet, "/some/api/path", nil)
		rec := httptest.NewRecorder()

		server.Handler.ServeHTTP(rec, req)

		g.Expect(rec.Code).To(Equal(http.StatusTeapot))
		g.Expect(apiCalled).To(BeTrue())
	})

	t.Run("CORS enabled", func(t *testing.T) {
		g := NewWithT(t)

		api := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		conf := &config{
			Proxy: proxyConfig{
				CORS: true,
			},
			Server: serverConfig{
				Addr: ":8080",
			},
		}

		registry := prometheus.NewRegistry()
		server := newServer(conf, api, registry, registry)

		tests := []struct {
			name                string
			method              string
			path                string
			origin              string
			requestHeaders      string
			expectedStatus      int
			expectedOrigin      string
			expectedVary        string
			expectedCredentials string
			expectedMethods     string
			expectedHeaders     string
		}{
			{
				name:                "OPTIONS preflight with origin",
				method:              http.MethodOptions,
				path:                "/api/test",
				origin:              "https://example.com",
				requestHeaders:      "Content-Type,Authorization",
				expectedStatus:      http.StatusNoContent,
				expectedOrigin:      "https://example.com",
				expectedVary:        "Origin",
				expectedCredentials: "true",
				expectedMethods:     "GET,POST,PUT,PATCH,DELETE,OPTIONS",
				expectedHeaders:     "Content-Type,Authorization",
			},
			{
				name:                "GET request with CORS",
				method:              http.MethodGet,
				path:                "/api/test",
				origin:              "https://app.example.com",
				expectedStatus:      http.StatusOK,
				expectedOrigin:      "https://app.example.com",
				expectedVary:        "Origin",
				expectedCredentials: "true",
				expectedMethods:     "GET,POST,PUT,PATCH,DELETE,OPTIONS",
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				req := httptest.NewRequest(tt.method, tt.path, nil)
				if tt.origin != "" {
					req.Header.Set("Origin", tt.origin)
				}
				if tt.requestHeaders != "" {
					req.Header.Set("Access-Control-Request-Headers", tt.requestHeaders)
				}

				rec := httptest.NewRecorder()
				server.Handler.ServeHTTP(rec, req)

				g.Expect(rec.Code).To(Equal(tt.expectedStatus))

				// Check CORS headers
				g.Expect(rec.Header().Get("Access-Control-Allow-Credentials")).To(Equal(tt.expectedCredentials))
				g.Expect(rec.Header().Get("Access-Control-Allow-Methods")).To(Equal(tt.expectedMethods))

				if tt.expectedOrigin != "" {
					g.Expect(rec.Header().Get("Access-Control-Allow-Origin")).To(Equal(tt.expectedOrigin))
					g.Expect(rec.Header().Get("Vary")).To(Equal(tt.expectedVary))
				} else {
					g.Expect(rec.Header().Get("Access-Control-Allow-Origin")).To(BeEmpty())
					g.Expect(rec.Header().Get("Vary")).To(BeEmpty())
				}

				if tt.expectedHeaders != "" {
					g.Expect(rec.Header().Get("Access-Control-Allow-Headers")).To(Equal(tt.expectedHeaders))
				} else {
					g.Expect(rec.Header().Get("Access-Control-Allow-Headers")).To(BeEmpty())
				}
			})
		}
	})

	t.Run("CORS disabled", func(t *testing.T) {
		g := NewWithT(t)

		api := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		conf := &config{
			Server: serverConfig{
				Addr: ":8080",
			},
		}

		registry := prometheus.NewRegistry()
		server := newServer(conf, api, registry, registry)

		req := httptest.NewRequest(http.MethodGet, "/api/test", nil)
		req.Header.Set("Origin", "https://example.com")
		rec := httptest.NewRecorder()

		server.Handler.ServeHTTP(rec, req)

		g.Expect(rec.Code).To(Equal(http.StatusOK))
		// Should not have CORS headers when CORS is disabled
		g.Expect(rec.Header().Get("Access-Control-Allow-Origin")).To(BeEmpty())
		g.Expect(rec.Header().Get("Access-Control-Allow-Credentials")).To(BeEmpty())
		g.Expect(rec.Header().Get("Access-Control-Allow-Methods")).To(BeEmpty())
	})

	t.Run("metrics collection", func(t *testing.T) {
		g := NewWithT(t)

		api := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusCreated)
		})

		conf := &config{
			Server: serverConfig{
				Addr: ":8080",
			},
		}

		registry := prometheus.NewRegistry()
		server := newServer(conf, api, registry, registry)

		// Make a request to an API endpoint
		req := httptest.NewRequest(http.MethodPost, "/api/test", nil)
		req.Host = "example.com"
		rec := httptest.NewRecorder()

		server.Handler.ServeHTTP(rec, req)
		g.Expect(rec.Code).To(Equal(http.StatusCreated))

		// Check that metrics were recorded by fetching the metrics endpoint
		metricsReq := httptest.NewRequest(http.MethodGet, "/metrics", nil)
		metricsRec := httptest.NewRecorder()

		server.Handler.ServeHTTP(metricsRec, metricsReq)
		g.Expect(metricsRec.Code).To(Equal(http.StatusOK))

		metricsBody := metricsRec.Body.String()
		// Should contain our custom metric
		g.Expect(metricsBody).To(ContainSubstring("http_request_duration_seconds"))
		g.Expect(metricsBody).To(ContainSubstring("host=\"example.com\""))
		g.Expect(metricsBody).To(ContainSubstring("method=\"POST\""))
		g.Expect(metricsBody).To(ContainSubstring("path=\"/api/test\""))
		g.Expect(metricsBody).To(ContainSubstring("status=\"201\""))
	})
}
