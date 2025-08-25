IMG := ghcr.io/matheuscscp/mcp-oauth2-proxy/test:latest

PLATFORM := linux/amd64

.PHONY: run
run:
	MCP_OAUTH2_PROXY_CONFIG=config.yaml go run .

.PHONY: tidy
tidy:
	go mod tidy

.PHONY: test
test:
	go test -v -race -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html

.PHONY: docker-build
docker-build:
	docker buildx build -t $(IMG) --load --platform=$(PLATFORM) .

.PHONY: docker-push
docker-push:
	docker push $(IMG)
