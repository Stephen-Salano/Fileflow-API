# Spring Security Example Project

A comprehensive Spring Boot application demonstrating advanced security implementations using Spring Security 6.x with JWT (JSON Web Token) authentication.

## 🚀 Features

- **JWT Authentication**
    - Access and Refresh token implementation
    - Token-based authentication flow
    - Secure token generation and validation
    - Automatic token refresh mechanism

- **User Management**
    - User registration with role-based access
    - Support for multiple roles (USER, ADMIN)
    - Email or username-based authentication
    - Secure password encoding using BCrypt

- **Security Configuration**
    - Stateless session management
    - CORS configuration
    - Protected endpoints with role-based authorization
    - Custom JWT authentication filter

- **API Endpoints**
    - Public endpoints for authentication
    - Protected endpoints based on user roles
    - Support for file/image uploads with authentication
    - Comprehensive error handling

## 🛠 Tech Stack

- Java 21
- Spring Boot 3.4.4
- Spring Security
- Spring Data JPA
- PostgreSQL
- JSON Web Tokens (JWT)
- Lombok
- Log4j2 for logging
- Maven

## 📋 Prerequisites

- JDK 21
- Maven
- PostgreSQL database
- Your favorite IDE (e.g., IntelliJ IDEA, Eclipse)

## 🔧 Configuration

1. Clone the repository:
```bash
git clone https://github.com/Stephen-Salano/Spring_Security_example.git
```

2. Configure your database connection in `application.properties` or `application.yml`:
```yaml
spring:
  datasource:
    url: jdbc:postgresql://localhost:5432/your_database
    username: your_username
    password: your_password
```

3. Configure JWT properties:
```yaml
jwt:
  secret-key: your_secret_key
  access-token-expiration: 900000  # 15 minutes in milliseconds
  refresh-token-expiration: 604800000  # 7 days in milliseconds
```

## 🚀 Running the Application

1. Build the project:
```bash
mvn clean install
```

2. Run the application:
```bash
mvn spring-boot:run
```

## 🔒 API Endpoints

### Authentication Endpoints
```
POST /api/v1/auth/register - Register a new user
POST /api/v1/auth/authenticate - Authenticate user and get tokens
POST /api/v1/auth/refresh-token - Refresh access token
POST /api/v1/auth/logout - Logout user
```

### Protected Endpoints
```
/admin/** - Accessible by ADMIN role only
/user/** - Accessible by USER role
/api/v1/images/** - Protected image endpoints (GET requests are public)
```

## 🔐 Security Implementation Details

### JWT Authentication Flow

1. **Registration**:
    - User registers with basic information
    - Password is encoded using BCrypt
    - Default USER role is assigned if no role specified
    - Access and refresh tokens are generated

2. **Authentication**:
    - Supports both username and email authentication
    - Validates credentials
    - Returns JWT access and refresh tokens

3. **Token Validation**:
    - JWT tokens are validated on each request
    - Custom `JwtAuthenticationFilter` processes token
    - Automatic token refresh when expired

### Security Configuration

The project implements a robust security configuration:

```java
@Configuration
@EnableWebSecurity
public class SecurityConfig {
    // Stateless session management
    // Role-based authorization
    // Custom JWT authentication
    // CORS configuration
}
```

## 📝 Logging

The application uses Log4j2 for comprehensive logging:
- Authentication attempts
- Token validation
- Security events
- API access logs

## 🤝 Contributing

Contributions are welcome! Please feel free to submit pull requests.

1. Fork the repository
2. Create your feature branch
3. Commit your changes
4. Push to the branch
5. Open a pull request

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.