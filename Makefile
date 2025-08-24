IMG := ghcr.io/matheuscscp/mcp-oauth2-proxy/test:feat-v1

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

.PHONY: docker-build
docker-build:
	docker buildx build \
		--platform=$(PLATFORM) \
		-t $(IMG) .

.PHONY: docker-push
docker-push:
	docker push $(IMG)
