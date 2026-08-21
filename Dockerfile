# syntax=docker/dockerfile:1

# This service is self-contained: the build context is this directory, and
# there are no sibling modules to copy in.
FROM golang:1.25-alpine AS builder

RUN apk add --no-cache ca-certificates git

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .

# CGO off produces a static binary that runs on a minimal base.
RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags="-s -w" \
    -o /out/server ./cmd/server

FROM alpine:3.20

RUN apk add --no-cache ca-certificates tzdata && \
    adduser -D -u 10001 karlo

COPY --from=builder /out/server /usr/local/bin/server
COPY --from=builder /src/migrations /migrations

USER karlo

ENV TZ=Asia/Jakarta
EXPOSE 5001 6001

ENTRYPOINT ["/usr/local/bin/server"]
