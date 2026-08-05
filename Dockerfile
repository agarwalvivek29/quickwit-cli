# Multi-stage build for qwproxy (used by docker-compose and manual builds).
FROM golang:1.26 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/qwproxy ./cmd/qwproxy

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/qwproxy /qwproxy
EXPOSE 9000
ENTRYPOINT ["/qwproxy"]
