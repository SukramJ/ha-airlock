# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 SukramJ.
#
# One static binary in an image without a shell. The Supervisor builds this
# file from the App directory and passes BUILD_VERSION.
FROM golang:1.27.4-alpine AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
ARG BUILD_VERSION=0.0.0-dev
ENV CGO_ENABLED=0
RUN go build -trimpath \
      -ldflags="-s -w -X github.com/SukramJ/ha-airlock/internal/build.Version=${BUILD_VERSION}" \
      -o /out/ha-airlock ./cmd/ha-airlock

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=builder /out/ha-airlock /app/ha-airlock
USER nonroot:nonroot
ENTRYPOINT ["/app/ha-airlock"]
CMD ["probe"]
