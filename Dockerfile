# syntax=docker/dockerfile:1

FROM golang:1.25.6 AS builder

ARG CGO_ENABLED=0
WORKDIR /app

RUN go env -w GOMODCACHE=/root/.cache/go-build

COPY . .

RUN --mount=type=cache,target=/root/.cache/go-build go mod download
RUN --mount=type=cache,target=/root/.cache/go-build go build -o ./bin/service

FROM scratch

WORKDIR /app

COPY --from=builder /app/bin/service ./service

COPY --from=ghcr.io/tarampampam/microcheck:1 /bin/httpcheck /bin/httpcheck
HEALTHCHECK --interval=1m --timeout=5s --start-period=10s --retries=3 CMD ["/bin/httpcheck", "http://localhost/health"]

ENTRYPOINT ["/app/service"]
