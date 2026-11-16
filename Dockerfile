# syntax=docker/dockerfile:1
FROM --platform=$BUILDPLATFORM golang:1.27.0-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download && go mod verify
COPY cmd/ ./cmd/
COPY internal/ ./internal/
ARG TARGETOS
ARG TARGETARCH
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -ldflags='-s -w' -o /out/xsync-server ./cmd/obsidiansync && \
    CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -ldflags='-s -w' -o /out/xsyncctl ./cmd/xsyncctl
RUN mkdir -p /runtime/objects && chown -R 65532:65532 /runtime

FROM scratch
COPY LICENSE /usr/share/licenses/xsync/LICENSE
COPY --from=build /out/xsync-server /out/xsyncctl /usr/local/bin/
COPY --from=build --chown=65532:65532 /runtime/ /data/
USER 65532:65532
WORKDIR /data
EXPOSE 8873
ENTRYPOINT ["/usr/local/bin/xsync-server"]
