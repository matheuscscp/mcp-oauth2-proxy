package main

import (
	"context"
	"net/http"

	"github.com/sirupsen/logrus"
)

type contextKeyLogger struct{}

func fromRequest(r *http.Request) logrus.FieldLogger {
	return fromContext(r.Context())
}

func fromContext(ctx context.Context) logrus.FieldLogger {
	if l := ctx.Value(contextKeyLogger{}); l != nil {
		return l.(logrus.FieldLogger)
	}
	return logrus.WithContext(ctx)
}

func intoRequest(r *http.Request, logger logrus.FieldLogger) *http.Request {
	return r.WithContext(intoContext(r.Context(), logger))
}

func intoContext(ctx context.Context, logger logrus.FieldLogger) context.Context {
	return context.WithValue(ctx, contextKeyLogger{}, logger)
}
