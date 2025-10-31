package logging

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
)

type contextKeyLogger struct{}

func init() {
	logrus.SetFormatter(&logrus.JSONFormatter{
		TimestampFormat: time.RFC3339Nano,
	})
}

func LoadLevel() error {
	logLevel := os.Getenv("LOG_LEVEL")
	if logLevel == "" {
		logLevel = logrus.InfoLevel.String()
	}
	level, err := logrus.ParseLevel(logLevel)
	if err != nil {
		allLevels := make([]string, 0, len(logrus.AllLevels))
		for _, l := range logrus.AllLevels {
			allLevels = append(allLevels, l.String())
		}
		allowedLevels := strings.Join(allLevels, ", ")
		logrus.SetLevel(logrus.InfoLevel)
		return fmt.Errorf("invalid LOG_LEVEL '%s', must be one of [%s]", logLevel, allowedLevels)
	}
	logrus.SetLevel(level)
	return nil
}

func FromRequest(r *http.Request) logrus.FieldLogger {
	return FromContext(r.Context())
}

func FromContext(ctx context.Context) logrus.FieldLogger {
	if l := ctx.Value(contextKeyLogger{}); l != nil {
		if logger, ok := l.(logrus.FieldLogger); ok {
			return logger
		}
	}
	return logrus.StandardLogger()
}

func IntoRequest(r *http.Request, logger logrus.FieldLogger) *http.Request {
	return r.WithContext(IntoContext(r.Context(), logger))
}

func IntoContext(ctx context.Context, logger logrus.FieldLogger) context.Context {
	return context.WithValue(ctx, contextKeyLogger{}, logger)
}
