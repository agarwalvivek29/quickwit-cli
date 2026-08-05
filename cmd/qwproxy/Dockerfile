# Release image for qwproxy — consumes the goreleaser-built binary from context.
FROM gcr.io/distroless/static-debian12:nonroot
COPY qwproxy /qwproxy
EXPOSE 9000
ENTRYPOINT ["/qwproxy"]
