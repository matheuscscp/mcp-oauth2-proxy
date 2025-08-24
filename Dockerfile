FROM golang:1.25.0-alpine3.21 AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY ./*.go ./

# CGO_ENABLED=0 to build a statically-linked binary
# -ldflags '-w -s' to strip debugging information for smaller size
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-w -s" -o mcp-oauth2-proxy \
    github.com/matheuscscp/mcp-oauth2-proxy

FROM alpine:3.22

COPY --from=builder /app/mcp-oauth2-proxy .

ENTRYPOINT ["./mcp-oauth2-proxy"]
