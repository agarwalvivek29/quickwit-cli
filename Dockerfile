# Multi-stage, multi-arch build for qwproxy.
# Used by docker-compose, `make`, and the GHCR publish workflow (buildx).
# --platform=$BUILDPLATFORM keeps the toolchain native and cross-compiles to
# $TARGETARCH, so arm64 images build fast on amd64 runners (no QEMU for `go build`).
FROM --platform=$BUILDPLATFORM golang:1.26 AS build
ARG TARGETOS
ARG TARGETARCH
ARG VERSION=dev
ARG COMMIT=none
ARG DATE=unknown
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -trimpath \
      -ldflags="-s -w -X main.version=${VERSION} -X main.commit=${COMMIT} -X main.date=${DATE}" \
      -o /out/qwproxy ./cmd/qwproxy

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/qwproxy /qwproxy
EXPOSE 9000
ENTRYPOINT ["/qwproxy"]
