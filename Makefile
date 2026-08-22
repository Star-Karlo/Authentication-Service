SERVICE      := authentication-service
MIGRATE_URL  ?= postgres://$(DB_USER):$(DB_PASSWORD)@$(DB_HOST):$(DB_PORT)/$(DB_NAME)?sslmode=disable

.PHONY: tools proto build run test test-integration test-integration-up test-integration-down lint tidy swagger migrate-up migrate-down migrate-create docker keys

# Install the development tooling this repo needs.
tools:
	go install github.com/bufbuild/buf/cmd/buf@latest
	go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
	go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest
	go install github.com/swaggo/swag/cmd/swag@v1.16.4
	go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@latest

# Regenerate the gRPC bindings from proto/.
#
# The contracts are duplicated across the service repos by design. When one
# changes, copy the updated .proto into every repo that speaks it and rerun
# this target there — otherwise the services drift apart silently, which is the
# cost this layout trades for full independence.
proto:
	cd proto && buf lint && buf generate
	go mod tidy

build:
	go build -o bin/server ./cmd/server

run:
	go run ./cmd/server

test:
	go test ./... -race

# Regenerate the OpenAPI document from the handler annotations.
# Requires: go install github.com/swaggo/swag/cmd/swag@v1.16.4
swagger:
	swag init -g cmd/server/main.go -o docs --parseDependency --parseInternal
	gofmt -w docs

# ---------------------------------------------------------------------------
# Integration tests
#
# These carry a build tag, so `make test` never compiles them, and they skip
# themselves when AUTH_TEST_DSN is unset. They cover what unit tests structurally
# cannot: real SQL, real indexes, and concurrency against a real transaction
# manager.
# ---------------------------------------------------------------------------

IT_PORT ?= 55432
AUTH_TEST_DSN ?= postgres://karlo:karlo@localhost:$(IT_PORT)/karlo_auth_test?sslmode=disable

# A throwaway database on a non-default port, so it cannot collide with a
# Postgres you already run or with another service's test container.
test-integration-up:
	docker run -d --name karlo-authentication-it-pg \
		-e POSTGRES_USER=karlo -e POSTGRES_PASSWORD=karlo -e POSTGRES_DB=karlo_auth_test \
		-p $(IT_PORT):5432 postgres:16-alpine
	@echo "waiting for postgres..."
	@# pg_isready is NOT sufficient: the official image starts a temporary
	@# server to run initdb, and pg_isready succeeds against that before the
	@# database exists. Poll for the database itself.
	@until docker exec karlo-authentication-it-pg psql -U karlo -d karlo_auth_test -c 'SELECT 1' >/dev/null 2>&1; do sleep 1; done
	@for f in migrations/*.up.sql; do \
		docker exec -i karlo-authentication-it-pg psql -U karlo -d karlo_auth_test -v ON_ERROR_STOP=1 < "$$f" >/dev/null; \
	done
	@echo "ready. Run 'make test-integration'."

test-integration-down:
	-docker rm -f karlo-authentication-it-pg

test-integration:
	AUTH_TEST_DSN="$(AUTH_TEST_DSN)" go test -tags=integration ./tests/integration/... -race -v

lint:
	golangci-lint run ./...

tidy:
	go mod tidy

# Requires golang-migrate: go install -tags 'postgres' github.com/golang-migrate/migrate/v4/cmd/migrate@latest
migrate-up:
	migrate -path migrations -database "$(MIGRATE_URL)" up

migrate-down:
	migrate -path migrations -database "$(MIGRATE_URL)" down 1

migrate-create:
	@test -n "$(NAME)" || (echo "usage: make migrate-create NAME=add_something" && exit 1)
	migrate -path migrations -database "$(MIGRATE_URL)" create -ext sql -dir migrations -seq $(NAME)

docker:
	docker build -t karlo/$(SERVICE):latest .

# keys generates a development RSA keypair for token signing. Production keys
# belong in AWS Secrets Manager, never in the repository.
keys:
	@mkdir -p .keys
	openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out .keys/jwt-private.pem
	openssl rsa -pubout -in .keys/jwt-private.pem -out .keys/jwt-public.pem
	@echo "Wrote .keys/jwt-private.pem and .keys/jwt-public.pem"
