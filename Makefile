IMG := ghcr.io/matheuscscp/mcp-oauth2-proxy/sfm:v2

PLATFORM := linux/amd64

.PHONY: run
run:
	MCP_OAUTH2_PROXY_CONFIG=config.yaml go run .

.PHONY: docker-build
docker-build:
	docker buildx build \
		--push \
		--platform=$(PLATFORM) \
		-t $(IMG) .
