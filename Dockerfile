# syntax=docker/dockerfile:1

FROM golang:1.26.5-alpine3.23 AS builder

RUN apk add --no-cache ca-certificates

ARG CGO_ENABLED=0
ARG SERVICE_VERSION=unknown
WORKDIR /app

RUN go env -w GOMODCACHE=/root/.cache/go-build

COPY . .

RUN --mount=type=cache,target=/root/.cache/go-build go mod download
RUN --mount=type=cache,target=/root/.cache/go-build go build -o ./bin/service
RUN printf "%s" "$SERVICE_VERSION" > /app/version.txt

FROM scratch

COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

WORKDIR /app

COPY --from=builder /app/bin/service ./service
COPY --from=builder /app/version.txt ./version.txt

COPY --from=ghcr.io/tarampampam/microcheck:1 /bin/httpcheck /bin/httpcheck
HEALTHCHECK --interval=1m --timeout=5s --start-period=10s --retries=3 CMD ["/bin/httpcheck", "http://localhost/health"]

ENTRYPOINT ["/app/service"]
