# syntax=docker/dockerfile:1.7

############################
# Build stage
############################
FROM --platform=$BUILDPLATFORM golang:1.23.2-alpine AS builder

WORKDIR /app
RUN apk add --no-cache git

COPY go.mod go.sum ./
RUN go mod download && go mod verify

COPY . .

ARG TARGETOS
ARG TARGETARCH
ARG TARGETVARIANT

RUN echo "Building for $TARGETOS/$TARGETARCH/$TARGETVARIANT" && \
    CGO_ENABLED=0 \
    GOOS=$TARGETOS \
    GOARCH=$TARGETARCH \
    GOARM=${TARGETVARIANT#v} \
    go build -o redfish_exporter

############################
# Runtime stage
############################
FROM alpine:3.19

WORKDIR /app
RUN apk add --no-cache ca-certificates tzdata && \
    adduser -D -H -h /app redfish_exporter

COPY --from=builder /app/redfish_exporter .

USER redfish_exporter
COPY *.yml ./

EXPOSE 9610
ENTRYPOINT ["./redfish_exporter"]
