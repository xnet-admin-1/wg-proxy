# Build stage
FROM golang:1.23-alpine AS builder

RUN apk add --no-cache git

WORKDIR /src
COPY go.mod ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /bin/wg-proxy ./cmd/wg-proxy/

# Runtime stage
FROM alpine:3.20

RUN apk add --no-cache ca-certificates curl

# Install wireproxy
RUN ARCH=$(uname -m) && \
    if [ "$ARCH" = "x86_64" ]; then ARCH="amd64"; fi && \
    if [ "$ARCH" = "aarch64" ]; then ARCH="arm64"; fi && \
    curl -fsSL "https://github.com/pufferffish/wireproxy/releases/latest/download/wireproxy_linux_${ARCH}.tar.gz" \
    | tar -xz -C /usr/local/bin/ wireproxy && \
    chmod +x /usr/local/bin/wireproxy

COPY --from=builder /bin/wg-proxy /usr/local/bin/wg-proxy

# Default config directory
RUN mkdir -p /etc/wg-proxy/configs

ENV WG_CONFIG_DIR=/etc/wg-proxy/configs
ENV WG_PROXY_ADDR=:1080
ENV WG_ADMIN_ADDR=:8080

EXPOSE 1080 8080

ENTRYPOINT ["wg-proxy"]
