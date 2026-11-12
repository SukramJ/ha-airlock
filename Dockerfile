# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 SukramJ.
#
# One static binary in an image without a shell. The Supervisor builds this
# file from the App directory and passes BUILD_VERSION.
FROM golang:1.27.4-alpine AS builder
WORKDIR /src
COPY go.mod go.sum ./
COPY vendor ./vendor
COPY cmd ./cmd
COPY internal ./internal
ARG BUILD_VERSION=0.0.0-dev
ENV CGO_ENABLED=0
# Dependencies come from vendor/; the build fetches nothing.
RUN go build -mod=vendor -trimpath \
      -ldflags="-s -w -X github.com/SukramJ/ha-airlock/internal/build.Version=${BUILD_VERSION}" \
      -o /out/ha-airlock ./cmd/ha-airlock

# The process runs as root inside the container: the Supervisor creates the
# App's /data directory as root and does not hand it over
# (supervisor/apps/app.py:998-1002 at 98a2322), and the audit log and the
# credential live there. The container itself gets no extra privilege.
FROM gcr.io/distroless/static-debian12
COPY --from=builder /out/ha-airlock /app/ha-airlock
ENTRYPOINT ["/app/ha-airlock"]
CMD ["provision"]
