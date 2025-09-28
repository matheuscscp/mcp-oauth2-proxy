package logging

import (
	"context"
	"net/http"

	"github.com/sirupsen/logrus"
)

type contextKeyLogger struct{}

func FromRequest(r *http.Request) logrus.FieldLogger {
	return FromContext(r.Context())
}

func FromContext(ctx context.Context) logrus.FieldLogger {
	if l := ctx.Value(contextKeyLogger{}); l != nil {
		if logger, ok := l.(logrus.FieldLogger); ok {
			return logger
		}
	}
	return logrus.WithContext(ctx)
}

func IntoRequest(r *http.Request, logger logrus.FieldLogger) *http.Request {
	return r.WithContext(IntoContext(r.Context(), logger))
}

func IntoContext(ctx context.Context, logger logrus.FieldLogger) context.Context {
	return context.WithValue(ctx, contextKeyLogger{}, logger)
}
