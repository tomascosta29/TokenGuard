## CostaAuth - Authentication Microservice

[![Go](https://img.shields.io/badge/Go-1.20+-00ADD8?style=for-the-badge&logo=go&logoColor=white)](https://go.dev/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Tests](https://github.com/tomascosta29/CostaAuth/actions/workflows/go.yml/badge.svg)](https://github.com/tomascosta29/CostaAuth/actions/workflows/go.yml) <!-- Replace with your actual GitHub Actions badge link -->

**CostaAuth** is a robust and secure authentication microservice built in Go. It provides essential authentication functionalities for securing your applications and microservice architectures. This project is designed with modularity, testability, and security best practices in mind.

## Features

*   **User Registration and Login:** Securely register new users and authenticate existing users using username/password credentials.
*   **JWT (JSON Web Token) Based Authentication:** Utilizes JWTs for stateless and scalable access token management.
*   **Refresh Tokens:** Implements refresh tokens for maintaining user sessions securely and enabling token rotation, improving security and user experience.
*   **Token Revocation (Logout):** Allows users to securely log out by invalidating access and refresh tokens.
*   **Token Validation:** Provides an endpoint to validate JWT access tokens, ensuring secure access to protected resources.
*   **Flexible Token Storage:** Supports both **Redis** (for production, scalable setups) and **In-Memory** (for development, testing) token storage for revocation and refresh token management, configurable via environment variables.
*   **SQLite User Database:** Uses SQLite as a lightweight and file-based database for user data storage, suitable for development and smaller deployments.
*   **Password Complexity Validation:** Enforces strong password policies during registration, requiring minimum length, uppercase, lowercase, numbers, and special characters.
*   **Bcrypt Password Hashing:** Securely hashes user passwords using bcrypt, a widely trusted and robust hashing algorithm.
*   **Mutual TLS (mTLS) Support (Optional):**  Offers optional mTLS support for enhanced security in environments requiring mutual authentication between client and server, configurable via environment variables and certificate files.
*   **Graceful Shutdown:** Implements graceful shutdown to ensure clean server termination and prevent data loss during restarts or shutdowns.
*   **Comprehensive Unit Tests:**  Includes extensive unit tests covering handlers, services, and repositories, ensuring code quality and reliability.
*   **Configuration via `.env` files:**  Loads configuration from `.env` files for easy environment management and separation of configuration from code.

## Technologies Used

*   **Go:** Programming language for building the microservice.
*   **[gorilla/mux](https://github.com/gorilla/mux):**  Powerful HTTP request router and dispatcher.
*   **[golang-jwt/jwt/v5](https://github.com/golang-jwt/jwt/v5):**  Library for working with JSON Web Tokens (JWT).
*   **[go-redis/redis/v8](https://github.com/go-redis/redis/v8):**  Redis client for Go.
*   **[mattn/go-sqlite3](https://github.com/mattn/go-sqlite3):**  SQLite driver for Go.
*   **[joho/godotenv](https://github.com/joho/godotenv):**  For loading environment variables from `.env` files.
*   **[stretchr/testify](https://github.com/stretchr/testify):**  Suite of Go testing tools, including assertions and mocks.
*   **[google/uuid](https://github.com/google/uuid):**  For generating UUIDs (Universally Unique Identifiers).
*   **[golang.org/x/crypto/bcrypt](https://pkg.go.dev/golang.org/x/crypto/bcrypt):** For secure password hashing.

## Getting Started

### Prerequisites

*   **Go:**  Make sure you have Go version 1.20 or later installed. You can download it from [https://go.dev/dl/](https://go.dev/dl/).
*   **Redis (Optional):** If you plan to use Redis for token storage (recommended for production), ensure you have a Redis instance running and accessible. You can download and install Redis from [https://redis.io/download/](https://redis.io/download/).
*   **Certificates for mTLS (Optional):** If you want to enable mTLS, you'll need to generate or obtain server and CA certificates and keys.

### Installation and Running

1.  **Clone the repository:**

    ```bash
    git clone <repository-url>
    cd CostaAuth
    ```

2.  **Create `.env` file:**

    Copy the `.env.example` file to `.env` and modify the environment variables according to your setup.

    ```bash
    cp .env.example .env
    ```

    **Example `.env` content:**

    ```env
    PORT=8080
    JWT_SECRET="your-secret-jwt-key"  # Replace with a strong, secret key
    TOKEN_STORE=inmemory        # Options: inmemory, redis
    REDIS_ADDRESS=localhost:6379  # Required if TOKEN_STORE=redis
    REDIS_PASSWORD=""           # Redis password (if any)
    MTLS_ENABLED=false          # Set to true to enable mTLS
    SERVER_CERT_FILE=certs/server.crt # Path to server certificate (mTLS)
    SERVER_KEY_FILE=certs/server.key  # Path to server key (mTLS)
    CA_CERT_FILE=certs/ca.crt      # Path to CA certificate (mTLS)
    ```

    **Important:**

    *   **`JWT_SECRET`**:  **Replace `"your-secret-jwt-key"` with a strong, randomly generated secret key.** Keep this key secure.
    *   **`TOKEN_STORE`**: Choose between `inmemory` (for development/testing) or `redis` (for production).
    *   **Redis Variables**: If using `redis`, configure `REDIS_ADDRESS` and `REDIS_PASSWORD` accordingly.
    *   **mTLS Variables**: If enabling `MTLS_ENABLED=true`, ensure `SERVER_CERT_FILE`, `SERVER_KEY_FILE`, and `CA_CERT_FILE` are correctly pointing to your certificate files.

3.  **Run the service:**

    ```bash
    go run ./cmd/costa-auth/main.go
    ```

    The service will start on the port specified in your `.env` file (default is `8080`). Check the logs for successful startup messages.

## Testing

To run the unit tests, execute the following command from the project root directory:

```bash
go test ./... CostaAuth

**Future Work:** (in no specific order)

*   Expanded Database Support (PostgreSQL, MySQL etc.)
*   Email Verification
*   Password Reset Functionality
*   Rate Limiting
*   Metrics and Monitoring (Prometheus, Grafana)
*   Audit Logging
*   OAuth 2.0 Support
*   Social Login
*   Multi-Factor Authentication (MFA)
*   Detailed Error Responses
*   API Versioning
*   Improved Input Validation
