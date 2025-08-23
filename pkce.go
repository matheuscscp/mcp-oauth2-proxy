package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
)

func pkceVerifier() (string, error) {
	// RFC 7636: 43..128 chars from ALPHA / DIGIT / "-" / "." / "_" / "~"
	// https://datatracker.ietf.org/doc/html/rfc7636#section-4.1
	const allowed = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~"
	const n = 64 // any length 43-128
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	for i := range buf {
		buf[i] = allowed[int(buf[i])%len(allowed)]
	}
	return string(buf), nil
}

func pkceS256Challenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}
