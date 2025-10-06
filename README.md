# HTTP Server - Go REST API

A robust, production-ready HTTP server built with Go, featuring user authentication, JWT tokens, password hashing, webhook integration, and a complete REST API for a social media platform called "Chirpy".

## 🚀 Features

### Authentication & Security
- **JWT Authentication**: Secure access tokens with configurable expiration
- **Refresh Tokens**: Long-lived tokens for seamless user sessions
- **Password Hashing**: Argon2id for secure password storage
- **API Key Authentication**: Webhook security with Polka integration
- **Environment Variables**: Secure configuration management

### User Management
- **User Registration**: Create accounts with email and password
- **User Login**: JWT-based authentication with refresh tokens
- **User Updates**: Authenticated profile updates
- **Chirpy Red Membership**: Premium user tier with webhook integration

### Social Features
- **Chirps**: Create, read, update, and delete social media posts
- **Author Filtering**: Filter chirps by specific authors
- **Sorting**: Flexible sorting by creation date (ascending/descending)
- **Character Validation**: 140-character limit with profanity filtering

### Database & Performance
- **PostgreSQL**: Robust relational database
- **SQLC**: Type-safe SQL code generation
- **Database Migrations**: Goose for schema management
- **Connection Pooling**: Efficient database connections
- **Context Support**: Request timeout handling

## 🛠️ Tech Stack

- **Language**: Go 1.21+
- **Database**: PostgreSQL
- **ORM**: SQLC for type-safe queries
- **Migrations**: Goose
- **Authentication**: JWT (golang-jwt/jwt/v5)
- **Password Hashing**: Argon2id
- **Environment**: godotenv
- **UUID**: google/uuid

## 📋 API Endpoints

### Authentication
- `POST /api/users` - Create user account
- `POST /api/login` - User login (returns JWT + refresh token)
- `POST /api/refresh` - Refresh access token
- `POST /api/revoke` - Revoke refresh token
- `PUT /api/users` - Update user profile (authenticated)

### Chirps
- `GET /api/chirps` - Get all chirps (with optional filtering & sorting)
- `GET /api/chirps?author_id=UUID` - Get chirps by author
- `GET /api/chirps?sort=asc|desc` - Sort chirps by date
- `GET /api/chirps/{id}` - Get specific chirp
- `POST /api/chirps` - Create chirp (authenticated)
- `DELETE /api/chirps/{id}` - Delete chirp (authenticated, author only)

### Webhooks
- `POST /api/polka/webhooks` - Polka payment webhook (API key protected)

### Admin
- `POST /admin/reset` - Reset database (dev environment only)

## 🚦 Quick Start

### Prerequisites
- Go 1.21 or later
- PostgreSQL 12 or later
- Git

### Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/PassZ/http-server.git
   cd http-server
   ```

2. **Install dependencies**
   ```bash
   go mod tidy
   ```

3. **Set up PostgreSQL database**
   ```bash
   createdb chirpy
   ```

4. **Configure environment**
   ```bash
   cp .env.example .env
   # Edit .env with your database URL and secrets
   ```

5. **Run database migrations**
   ```bash
   goose -dir sql/schema postgres "your-db-url" up
   ```

6. **Generate SQLC code**
   ```bash
   sqlc generate
   ```

7. **Build and run**
   ```bash
   go build -o http-server
   ./http-server
   ```

The server will start on `http://localhost:8080`

## 🔧 Configuration

Create a `.env` file in the root directory:

```env
PLATFORM=dev
DB_URL=postgres://username:password@localhost:5432/chirpy?sslmode=disable
JWT_SECRET=your-jwt-secret-here
POLKA_KEY=your-polka-api-key-here
```

## 📊 Database Schema

### Users Table
- `id` (UUID, Primary Key)
- `email` (TEXT, Unique)
- `hashed_password` (TEXT)
- `is_chirpy_red` (BOOLEAN, Default: false)
- `created_at` (TIMESTAMP)
- `updated_at` (TIMESTAMP)

### Chirps Table
- `id` (UUID, Primary Key)
- `body` (TEXT, Max 140 characters)
- `user_id` (UUID, Foreign Key to users)
- `created_at` (TIMESTAMP)
- `updated_at` (TIMESTAMP)

### Refresh Tokens Table
- `token` (TEXT, Primary Key)
- `user_id` (UUID, Foreign Key to users)
- `expires_at` (TIMESTAMP)
- `revoked_at` (TIMESTAMP, Nullable)
- `created_at` (TIMESTAMP)
- `updated_at` (TIMESTAMP)

## 🔐 Security Features

- **Password Security**: Argon2id hashing with salt
- **JWT Security**: HMAC-SHA256 signing with configurable secrets
- **Token Expiration**: Short-lived access tokens (1 hour) + long-lived refresh tokens (60 days)
- **API Key Protection**: Webhook endpoints protected with API keys
- **Input Validation**: Comprehensive request validation
- **SQL Injection Prevention**: Parameterized queries via SQLC

## 🧪 Testing

### Manual Testing
```bash
# Create a user
curl -X POST http://localhost:8080/api/users \
  -H "Content-Type: application/json" \
  -d '{"email": "test@example.com", "password": "password123"}'

# Login
curl -X POST http://localhost:8080/api/login \
  -H "Content-Type: application/json" \
  -d '{"email": "test@example.com", "password": "password123"}'

# Create a chirp (use token from login response)
curl -X POST http://localhost:8080/api/chirps \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -d '{"body": "Hello, world!"}'

# Get all chirps
curl http://localhost:8080/api/chirps

# Get chirps sorted by date (newest first)
curl "http://localhost:8080/api/chirps?sort=desc"
```

## 📈 Performance Considerations

- **Database Indexing**: Proper indexes on frequently queried columns
- **Connection Pooling**: Efficient database connection management
- **In-Memory Sorting**: Fast sorting for typical data volumes
- **Context Timeouts**: Request timeout handling to prevent hanging connections
- **Efficient Queries**: SQLC-generated queries optimized for performance

## 🏗️ Architecture

```
├── cmd/
│   └── server/
├── internal/
│   ├── auth/          # Authentication utilities
│   └── database/      # Database models and queries
├── sql/
│   ├── schema/        # Database migrations
│   └── queries/       # SQLC query definitions
├── main.go           # Application entry point
├── go.mod            # Go module dependencies
└── README.md         # This file
```
