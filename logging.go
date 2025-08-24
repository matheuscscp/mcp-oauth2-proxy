package main

import (
	"context"
	"net/http"

	"github.com/sirupsen/logrus"
)

type contextKeyLogger struct{}

func fromRequest(r *http.Request) logrus.FieldLogger {
	if l := r.Context().Value(contextKeyLogger{}); l != nil {
		return l.(logrus.FieldLogger)
	}
	return logrus.WithContext(r.Context())
}

func intoRequest(r *http.Request, logger logrus.FieldLogger) *http.Request {
	ctx := context.WithValue(r.Context(), contextKeyLogger{}, logger)
	return r.WithContext(ctx)
}
