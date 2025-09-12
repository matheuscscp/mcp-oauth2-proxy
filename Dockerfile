FROM golang:1.25.1-alpine3.21 AS builder

WORKDIR /workspace

COPY go.mod go.sum ./
RUN go mod download

COPY ./*.go ./

# CGO_ENABLED=0 to build a statically-linked binary
# -ldflags '-w -s' to strip debugging information for smaller size
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-w -s" -o mcp-oauth2-proxy \
    github.com/matheuscscp/mcp-oauth2-proxy

FROM gcr.io/distroless/static:nonroot
WORKDIR /
COPY LICENSE /licenses/LICENSE
COPY --from=builder /workspace/mcp-oauth2-proxy .
USER 65532:65532
ENTRYPOINT ["/mcp-oauth2-proxy"]
