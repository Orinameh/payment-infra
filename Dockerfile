# ── Build stage ────────────────────────────────────────────────
FROM golang:1.26-alpine3.23 AS builder

RUN apk --no-cache add ca-certificates tzdata git

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download && go mod verify

COPY . .

ARG VERSION=dev
ARG COMMIT=unknown
RUN CGO_ENABLED=0 GOOS=linux \
    go build -trimpath -ldflags="-s -w -X main.version=${VERSION} -X main.commit=${COMMIT}" \
      -o /out/api ./cmd/api && \
    CGO_ENABLED=0 GOOS=linux \
    go build -trimpath -ldflags="-s -w" \
      -o /out/worker ./cmd/worker && \
    CGO_ENABLED=0 GOOS=linux \
    go build -trimpath -ldflags="-s -w" \
      -o /out/migrate ./cmd/migrate

# ── Runtime stage ──────────────────────────────────────────────
FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /usr/share/zoneinfo /usr/share/zoneinfo
COPY --from=builder /out/api     /app/api
COPY --from=builder /out/worker  /app/worker
COPY --from=builder /out/migrate /app/migrate

WORKDIR /app
USER nonroot:nonroot
EXPOSE 8443
ENTRYPOINT ["/app/api"]