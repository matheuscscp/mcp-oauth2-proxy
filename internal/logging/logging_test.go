package logging

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	. "github.com/onsi/gomega"
	"github.com/sirupsen/logrus"
)

// mockFieldLogger implements logrus.FieldLogger for testing
type mockFieldLogger struct {
	logrus.FieldLogger
	fields map[string]any
}

func newMockFieldLogger() *mockFieldLogger {
	return &mockFieldLogger{
		fields: make(map[string]any),
	}
}

func (m *mockFieldLogger) WithField(key string, value any) *logrus.Entry {
	m.fields[key] = value
	return logrus.NewEntry(logrus.StandardLogger())
}

func (m *mockFieldLogger) WithFields(fields logrus.Fields) *logrus.Entry {
	for k, v := range fields {
		m.fields[k] = v
	}
	return logrus.NewEntry(logrus.StandardLogger())
}

func (m *mockFieldLogger) WithError(err error) *logrus.Entry {
	m.fields["error"] = err
	return logrus.NewEntry(logrus.StandardLogger())
}

func (m *mockFieldLogger) WithContext(ctx context.Context) *logrus.Entry {
	return logrus.NewEntry(logrus.StandardLogger())
}

func (m *mockFieldLogger) WithTime(t time.Time) *logrus.Entry {
	return logrus.NewEntry(logrus.StandardLogger())
}

func (m *mockFieldLogger) Debugf(format string, args ...any)   {}
func (m *mockFieldLogger) Infof(format string, args ...any)    {}
func (m *mockFieldLogger) Printf(format string, args ...any)   {}
func (m *mockFieldLogger) Warnf(format string, args ...any)    {}
func (m *mockFieldLogger) Warningf(format string, args ...any) {}
func (m *mockFieldLogger) Errorf(format string, args ...any)   {}
func (m *mockFieldLogger) Fatalf(format string, args ...any)   {}
func (m *mockFieldLogger) Panicf(format string, args ...any)   {}
func (m *mockFieldLogger) Debug(args ...any)                   {}
func (m *mockFieldLogger) Info(args ...any)                    {}
func (m *mockFieldLogger) Print(args ...any)                   {}
func (m *mockFieldLogger) Warn(args ...any)                    {}
func (m *mockFieldLogger) Warning(args ...any)                 {}
func (m *mockFieldLogger) Error(args ...any)                   {}
func (m *mockFieldLogger) Fatal(args ...any)                   {}
func (m *mockFieldLogger) Panic(args ...any)                   {}
func (m *mockFieldLogger) Debugln(args ...any)                 {}
func (m *mockFieldLogger) Infoln(args ...any)                  {}
func (m *mockFieldLogger) Println(args ...any)                 {}
func (m *mockFieldLogger) Warnln(args ...any)                  {}
func (m *mockFieldLogger) Warningln(args ...any)               {}
func (m *mockFieldLogger) Errorln(args ...any)                 {}
func (m *mockFieldLogger) Fatalln(args ...any)                 {}
func (m *mockFieldLogger) Panicln(args ...any)                 {}

func TestLoadLevel(t *testing.T) {
	t.Run("default level", func(t *testing.T) {
		g := NewWithT(t)
		err := LoadLevel()
		g.Expect(err).NotTo(HaveOccurred())
		l := logrus.GetLevel()
		g.Expect(l).To(Equal(logrus.InfoLevel))
	})

	t.Run("valid level", func(t *testing.T) {
		g := NewWithT(t)
		t.Setenv("LOG_LEVEL", "debug")
		err := LoadLevel()
		g.Expect(err).NotTo(HaveOccurred())
		l := logrus.GetLevel()
		g.Expect(l).To(Equal(logrus.DebugLevel))
	})

	t.Run("invalid level", func(t *testing.T) {
		g := NewWithT(t)
		t.Setenv("LOG_LEVEL", "invalid-level")
		err := LoadLevel()
		g.Expect(err).To(MatchError("invalid LOG_LEVEL 'invalid-level', must be one of [panic, fatal, error, warning, info, debug, trace]"))
	})
}

func TestFromContext(t *testing.T) {
	tests := []struct {
		name         string
		setupContext func() context.Context
		expectCustom bool
	}{
		{
			name: "context with logger",
			setupContext: func() context.Context {
				ctx := context.Background()
				logger := newMockFieldLogger()
				return IntoContext(ctx, logger)
			},
			expectCustom: true,
		},
		{
			name: "context without logger",
			setupContext: func() context.Context {
				return context.Background()
			},
			expectCustom: false,
		},
		{
			name: "context with nil value",
			setupContext: func() context.Context {
				ctx := context.Background()
				// Directly set nil to test edge case
				return context.WithValue(ctx, contextKeyLogger{}, nil)
			},
			expectCustom: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			ctx := tt.setupContext()
			logger := FromContext(ctx)

			g.Expect(logger).ToNot(BeNil())

			if tt.expectCustom {
				// If we expect a custom logger, it should be the one we put in
				storedLogger := ctx.Value(contextKeyLogger{})
				g.Expect(storedLogger).ToNot(BeNil())
				// The returned logger should be the same as the stored one
				g.Expect(logger).To(Equal(storedLogger))
			} else {
				// If no custom logger, it should return a logrus Logger
				_, ok := logger.(*logrus.Logger)
				g.Expect(ok).To(BeTrue())
			}
		})
	}
}

func TestFromRequest(t *testing.T) {
	tests := []struct {
		name         string
		setupRequest func() *http.Request
		expectCustom bool
	}{
		{
			name: "request with logger in context",
			setupRequest: func() *http.Request {
				req := httptest.NewRequest("GET", "/test", nil)
				logger := newMockFieldLogger()
				return IntoRequest(req, logger)
			},
			expectCustom: true,
		},
		{
			name: "request without logger in context",
			setupRequest: func() *http.Request {
				return httptest.NewRequest("GET", "/test", nil)
			},
			expectCustom: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			req := tt.setupRequest()
			logger := FromRequest(req)

			g.Expect(logger).ToNot(BeNil())

			if tt.expectCustom {
				// If we expect a custom logger, verify it's in the context
				storedLogger := req.Context().Value(contextKeyLogger{})
				g.Expect(storedLogger).ToNot(BeNil())
				g.Expect(logger).To(Equal(storedLogger))
			} else {
				// If no custom logger, it should return a logrus logger
				_, ok := logger.(*logrus.Logger)
				g.Expect(ok).To(BeTrue())
			}
		})
	}
}

func TestIntoContext(t *testing.T) {
	g := NewWithT(t)

	// Create a mock logger
	logger := newMockFieldLogger()

	// Create a base context
	baseCtx := context.Background()

	// Add the logger to the context
	newCtx := IntoContext(baseCtx, logger)

	// Verify the logger is stored in the context
	storedValue := newCtx.Value(contextKeyLogger{})
	g.Expect(storedValue).ToNot(BeNil())
	g.Expect(storedValue).To(Equal(logger))

	// Verify we can retrieve it using FromContext
	retrievedLogger := FromContext(newCtx)
	g.Expect(retrievedLogger).To(Equal(logger))
}

func TestIntoRequest(t *testing.T) {
	g := NewWithT(t)

	// Create a mock logger
	logger := newMockFieldLogger()

	// Create a base request
	baseReq := httptest.NewRequest("GET", "/test", nil)

	// Add the logger to the request's context
	newReq := IntoRequest(baseReq, logger)

	// Verify the logger is stored in the request's context
	storedValue := newReq.Context().Value(contextKeyLogger{})
	g.Expect(storedValue).ToNot(BeNil())
	g.Expect(storedValue).To(Equal(logger))

	// Verify we can retrieve it using FromRequest
	retrievedLogger := FromRequest(newReq)
	g.Expect(retrievedLogger).To(Equal(logger))

	// Verify that the request is different from the original
	g.Expect(newReq).ToNot(Equal(baseReq))
}

func TestContextKeyIsolation(t *testing.T) {
	g := NewWithT(t)

	// Create two different loggers
	logger1 := newMockFieldLogger()
	logger1.fields["id"] = "logger1"

	logger2 := newMockFieldLogger()
	logger2.fields["id"] = "logger2"

	// Create two contexts with different loggers
	ctx1 := IntoContext(context.Background(), logger1)
	ctx2 := IntoContext(context.Background(), logger2)

	// Verify each context maintains its own logger
	retrieved1 := FromContext(ctx1)
	retrieved2 := FromContext(ctx2)

	g.Expect(retrieved1).To(Equal(logger1))
	g.Expect(retrieved2).To(Equal(logger2))
	g.Expect(retrieved1).ToNot(Equal(retrieved2))
}

func TestNestedContexts(t *testing.T) {
	g := NewWithT(t)

	// Create a parent context with a logger
	parentLogger := newMockFieldLogger()
	parentLogger.fields["level"] = "parent"
	parentCtx := IntoContext(context.Background(), parentLogger)

	// Create a child context with a different logger
	childLogger := newMockFieldLogger()
	childLogger.fields["level"] = "child"
	childCtx := IntoContext(parentCtx, childLogger)

	// Verify the child context has the child logger
	retrievedChild := FromContext(childCtx)
	g.Expect(retrievedChild).To(Equal(childLogger))

	// Verify the parent context still has the parent logger
	retrievedParent := FromContext(parentCtx)
	g.Expect(retrievedParent).To(Equal(parentLogger))
}

func TestRequestChaining(t *testing.T) {
	g := NewWithT(t)

	// Start with a base request
	req1 := httptest.NewRequest("GET", "/test", nil)

	// Add first logger
	logger1 := newMockFieldLogger()
	logger1.fields["step"] = 1
	req2 := IntoRequest(req1, logger1)

	// Add second logger (replacing the first)
	logger2 := newMockFieldLogger()
	logger2.fields["step"] = 2
	req3 := IntoRequest(req2, logger2)

	// Verify the final request has the second logger
	finalLogger := FromRequest(req3)
	g.Expect(finalLogger).To(Equal(logger2))

	// Verify intermediate request still has its logger
	intermediateLogger := FromRequest(req2)
	g.Expect(intermediateLogger).To(Equal(logger1))
}

func TestConcurrentAccess(t *testing.T) {
	g := NewWithT(t)

	// Create a context with a logger
	logger := newMockFieldLogger()
	ctx := IntoContext(context.Background(), logger)

	// Concurrently access the logger from multiple goroutines
	done := make(chan bool, 100)
	for range 100 {
		go func() {
			retrievedLogger := FromContext(ctx)
			g.Expect(retrievedLogger).To(Equal(logger))
			done <- true
		}()
	}

	// Wait for all goroutines to complete
	for i := 0; i < 100; i++ {
		<-done
	}
}

func TestWithRealLogrus(t *testing.T) {
	g := NewWithT(t)

	// Test with a real logrus entry
	entry := logrus.WithField("test", "value")
	ctx := IntoContext(context.Background(), entry)

	retrievedLogger := FromContext(ctx)
	g.Expect(retrievedLogger).To(Equal(entry))

	// Test that the logger can actually be used
	// This won't panic if the logger is valid
	retrievedLogger.Debug("test message")
}

func TestFromContextWithCanceledContext(t *testing.T) {
	g := NewWithT(t)

	// Create a cancellable context with a logger
	ctx, cancel := context.WithCancel(context.Background())
	logger := newMockFieldLogger()
	ctx = IntoContext(ctx, logger)

	// Cancel the context
	cancel()

	// We should still be able to retrieve the logger even from a cancelled context
	retrievedLogger := FromContext(ctx)
	g.Expect(retrievedLogger).To(Equal(logger))
}
