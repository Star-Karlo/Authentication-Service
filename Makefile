SERVICE      := authentication-service
MIGRATE_URL  ?= postgres://$(DB_USER):$(DB_PASSWORD)@$(DB_HOST):$(DB_PORT)/$(DB_NAME)?sslmode=disable

.PHONY: tools proto build run test test-integration lint tidy swagger migrate-up migrate-down migrate-create docker keys

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

# Integration tests run against a real database. They carry a build tag, so
# `make test` never picks them up, and they skip themselves when AUTH_TEST_DSN is
# unset. `make -C .. test-integration-up` starts throwaway containers.
AUTH_TEST_DSN ?= postgres://karlo:karlo@localhost:5432/karlo_auth_test?sslmode=disable

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
