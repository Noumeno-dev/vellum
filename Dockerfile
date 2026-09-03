# Stage 1: Build the frontend assets
FROM node:22-alpine AS frontend
WORKDIR /build/web
COPY web/package*.json ./
RUN npm ci --silent
COPY web/ ./
RUN npm run build

# Stage 2: Build the Go backend binary
FROM golang:1.26-alpine AS backend
WORKDIR /build
# Download dependencies first for better caching
COPY go.mod go.sum ./
RUN go mod download
COPY . .
# Copy the built frontend assets from the previous stage
COPY --from=frontend "/build/cmd/vellum/dist" "cmd/vellum/dist"
# Build the application with optimized flags
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o vellum ./cmd/vellum

# Stage 3: Final production image
FROM alpine:3.21

# Metadata according to the OpenContainers standard
LABEL org.opencontainers.image.title="Vellum"
LABEL org.opencontainers.image.description="SMTP testing server for modern teams - AGPLv3 or Commercial License"
LABEL org.opencontainers.image.vendor="Noumeno.dev"
LABEL org.opencontainers.image.authors="Gerbo (@Gerbo67)"
LABEL org.opencontainers.image.url="https://blog.noumeno.dev/vellum"
LABEL org.opencontainers.image.source="https://github.com/Gerbo67/vellum"
# Dual license definition
LABEL org.opencontainers.image.licenses="AGPL-3.0-only OR Commercial"
# Additional note on commercial offering
LABEL dev.noumeno.vellum.commercial="Contact via blog.noumeno.dev for commercial licensing (10 USD/mo)"

# Install essential certificates and timezone data
RUN apk add --no-cache ca-certificates tzdata

# Create a non-privileged user for security
RUN addgroup -S vellum && adduser -S vellum -G vellum

WORKDIR /app

# Copy the binary from the backend build stage
COPY --from=backend /build/vellum .

# Set up data directory with correct permissions
RUN mkdir -p /data && chown vellum:vellum /data

# Run as a non-root user
USER vellum

# Define persistence volume for data
VOLUME ["/data"]

# Expose Web UI and SMTP ports
EXPOSE 8025 2525

# Health check to ensure the service is responsive
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD wget -qO- http://localhost:8025/api/auth/setup-status || exit 1

# Launch the application
ENTRYPOINT ["./vellum"]

