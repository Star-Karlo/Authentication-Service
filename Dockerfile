# syntax=docker/dockerfile:1

# This service is self-contained: the build context is this directory, and
# there are no sibling modules to copy in.
FROM golang:1.25-alpine AS builder

RUN apk add --no-cache ca-certificates git

WORKDIR /src

COPY go.mod go.sum ./

# Cache mounts rather than layers.
#
# Without them every rebuild wrote the downloaded modules and the compiled
# objects into image layers, and BuildKit kept every version of those layers
# indefinitely — four services rebuilt a few times each is how a laptop runs out
# of disk. A cache mount is shared between builds and swept by the daemon's
# garbage collector, so it stays bounded AND makes rebuilds much faster, since
# nothing is recompiled that has not changed.
RUN --mount=type=cache,target=/go/pkg/mod \
    go mod download

COPY . .

# CGO off produces a static binary that runs on a minimal base.
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=linux go build \
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
