# --- Build Stage ---
FROM golang:1.21-alpine AS builder

# Set the working directory
WORKDIR /app

# Copy go module and sum files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy the source code
COPY . .

# Build the application
# CGO_ENABLED=0 is important for building a static binary that can run in a minimal container
# -o /app/token-guard specifies the output file name and location
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o /app/token-guard ./cmd/token-guard

# --- Final Stage ---
FROM alpine:latest

# Set a non-root user for security
RUN addgroup -S appgroup && adduser -S appuser -G appgroup
USER appuser

# Set the working directory
WORKDIR /app

# Copy the built binary from the builder stage
COPY --from=builder /app/token-guard .

# Copy the .env.example file, so users know what variables are needed.
# Note: In a real production environment, you would not use a .env file.
# You would inject environment variables via Kubernetes secrets, Docker secrets, or a similar mechanism.
COPY .env.example .

# Expose the application port
EXPOSE 8080

# The command to run the application
# The user will need to provide a .env file or set environment variables.
CMD ["./token-guard"]
