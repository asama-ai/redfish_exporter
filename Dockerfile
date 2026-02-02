# Build stage
FROM golang:1.23.2-alpine AS builder

WORKDIR /app

# Install build dependencies
RUN apk add --no-cache git

# Copy go.mod first
COPY go.mod ./

# Download dependencies and generate go.sum
RUN go mod download && go mod verify

# Copy the rest of the source code
COPY . .

# Build the binary (TARGETARCH is set by Docker buildx for multi-platform builds)
ARG TARGETARCH=amd64
RUN CGO_ENABLED=0 GOOS=linux GOARCH=${TARGETARCH} go build -o redfish_exporter

# Final stage
FROM alpine:3.19

WORKDIR /app

# Install runtime dependencies and create non-root user
RUN apk add --no-cache ca-certificates tzdata && \
    adduser -D -H -h /app redfish_exporter

# Copy the binary from builder
COPY --from=builder /app/redfish_exporter .

# Set ownership to non-root user
RUN chown -R redfish_exporter:redfish_exporter /app

# Use non-root user
USER redfish_exporter

# COPY *.go ./
COPY *.yml ./
COPY redfish_exporter* ./

# RUN go build .

EXPOSE 9610

ENTRYPOINT [ "./redfish_exporter" ]
