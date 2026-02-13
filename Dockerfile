FROM golang:1.24.11-bookworm AS builder

ARG APP_VERSION=3.22.0
ARG BUILD_ENV=dev

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    pkg-config \
    libfido2-dev \
    libcbor-dev \
    libsecret-1-dev \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=1 GOOS=linux \
    go build -trimpath \
    -ldflags="-s -w \
    -X github.com/ProtonMail/proton-bridge/v3/internal/constants.Version=${APP_VERSION} \
    -X github.com/ProtonMail/proton-bridge/v3/internal/constants.BuildEnv=${BUILD_ENV}" \
    -o /out/Desktop-Bridge ./cmd/Desktop-Bridge

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    libfido2-1 \
    libcbor0.8 \
    libsecret-1-0 \
    libssl3 \
    tzdata \
    && rm -rf /var/lib/apt/lists/*

RUN useradd --create-home --shell /usr/sbin/nologin bridge

WORKDIR /home/bridge

COPY --from=builder /out/Desktop-Bridge /usr/local/bin/Desktop-Bridge

USER bridge

ENV BRIDGE_WEB_ADMIN_USER=root
ENV BRIDGE_WEB_ADMIN_PASS=change-me
ENV BRIDGE_WEB_ALLOW_NON_LOOPBACK=1
ENV BRIDGE_BIND_HOST=0.0.0.0

EXPOSE 8081 1143 1025

ENTRYPOINT ["/usr/local/bin/Desktop-Bridge"]
CMD ["--web", "--web-addr", "0.0.0.0:8081"]
