## TokenGuard - Authentication Microservice

[![Go](https://img.shields.io/badge/Go-1.21+-00ADD8?style=for-the-badge&logo=go&logoColor=white)](https://go.dev/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Tests](https://github.com/tomascosta29/TokenGuard/actions/workflows/go.yml/badge.svg)](https://github.com/tomascosta29/TokenGuard/actions/workflows/go.yml)

**TokenGuard** is a robust and secure authentication microservice built in Go. It provides essential authentication functionalities for securing your applications and microservice architectures. This project is designed with modularity, testability, and security best practices in mind.

## Features

*   **API Versioning:** Endpoints are versioned (e.g., `/v1/...`) to ensure backward compatibility.
*   **Rate Limiting:** Protects against brute-force attacks by limiting the number of requests per IP address.
*   **User Registration and Login:** Securely register new users and authenticate existing users using username/password credentials.
*   **JWT (JSON Web Token) Based Authentication:** Utilizes JWTs for stateless and scalable access token management.
*   **Refresh Tokens:** Implements refresh tokens for maintaining user sessions securely and enabling token rotation, improving security and user experience.
*   **Token Revocation (Logout):** Allows users to securely log out by invalidating access and refresh tokens.
*   **Token Validation:** Provides an endpoint to validate JWT access tokens, ensuring secure access to protected resources.
*   **Flexible Token Storage:** Supports both **Redis** (for production, scalable setups) and **In-Memory** (for development, testing) token storage for revocation and refresh token management.
*   **SQLite User Database:** Uses SQLite as a lightweight, file-based database for user data storage.
*   **Password Complexity Validation:** Enforces strong password policies during registration.
*   **Bcrypt Password Hashing:** Securely hashes user passwords using bcrypt.
*   **Mutual TLS (mTLS) Support (Optional):** Offers optional mTLS support for enhanced security.
*   **Containerized:** Comes with a `Dockerfile` for easy containerization and deployment.
*   **Graceful Shutdown:** Implements graceful shutdown to ensure clean server termination.
*   **Comprehensive Unit Tests:** Includes extensive unit tests covering handlers, services, and repositories.
*   **Configuration via `.env` files:** Loads configuration from `.env` files for easy environment management.

## API Endpoints

All endpoints are prefixed with `/v1`.

*   `POST /auth/register`: Register a new user.
*   `POST /auth/login`: Authenticate a user and receive JWT and refresh tokens.
*   `POST /auth/refresh`: Obtain a new access token using a refresh token.
*   `POST /auth/logout`: Invalidate the current access token.
*   `GET /auth/validate`: Validate an access token.

## Technologies Used

*   **Go:** Programming language for building the microservice.
*   **Docker:** For containerization.
*   **[gorilla/mux](https://github.com/gorilla/mux):** Powerful HTTP request router.
*   **[golang-jwt/jwt/v5](https://github.com/golang-jwt/jwt/v5):** Library for JSON Web Tokens (JWT).
*   **[go-redis/redis/v8](https://github.com/go-redis/redis/v8):** Redis client for Go.
*   **[mattn/go-sqlite3](https://github.com/mattn/go-sqlite3):** SQLite driver for Go.
*   **[golang.org/x/time/rate](https://pkg.go.dev/golang.org/x/time/rate):** For rate limiting.
*   **[joho/godotenv](https://github.com/joho/godotenv):** For loading `.env` files.
*   **[stretchr/testify](https://github.com/stretchr/testify):** Go testing tools.

## Getting Started

### Prerequisites

*   **Go:** Version 1.21 or later.
*   **Docker:** For running the service in a container.
*   **Redis (Optional):** If using Redis for token storage.
*   **Certificates for mTLS (Optional):** For enabling mTLS.

### Installation and Running

1.  **Clone the repository:**
    ```bash
    git clone <repository-url>
    cd TokenGuard
    ```

2.  **Create `.env` file:**
    Copy `.env.example` to `.env` and customize the variables.

    ```bash
    cp .env.example .env
    ```

    **Example `.env` content:**
    ```env
    # Server configuration
    PORT=8080

    # JWT settings
    JWT_SECRET="your-secret-jwt-key"

    # Token storage (inmemory or redis)
    TOKEN_STORE=inmemory
    REDIS_ADDRESS=localhost:6379
    REDIS_PASSWORD=""

    # Rate Limiting
    RATE_LIMITER_ENABLED=true
    RATE_LIMIT=10  # requests per second
    RATE_BURST=5   # burst size

    # mTLS settings
    MTLS_ENABLED=false
    SERVER_CERT_FILE=certs/server.crt
    SERVER_KEY_FILE=certs/server.key
    CA_CERT_FILE=certs/ca.crt
    ```

3.  **Run the service:**
    ```bash
    go run ./cmd/token-guard/main.go
    ```

### Running with Docker

1.  **Build the Docker image:**
    ```bash
    docker build -t tokenguard .
    ```

2.  **Run the Docker container:**
    You can pass environment variables directly or use a `.env` file.
    ```bash
    docker run -p 8080:8080 --env-file .env --name tokenguard tokenguard
    ```

## Testing

To run the unit tests, execute the following command:
```bash
go test ./...
```

---

**Future Work:** (in no specific order)

*   Expanded Database Support (PostgreSQL, MySQL etc.)
*   Email Verification
*   Password Reset Functionality
*   Metrics and Monitoring (Prometheus, Grafana)
*   Audit Logging
*   OAuth 2.0 Support
*   Social Login
*   Multi-Factor Authentication (MFA)
*   Detailed Error Responses
*   Improved Input Validation
