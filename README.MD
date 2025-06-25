# FileFlow: Media Management & Social Platform

A modern Spring Boot application for secure media upload, processing, and social sharing with JWT authentication, FFmpeg optimization, Apache Tika metadata extraction, and cloud storage integration.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Spring Boot](https://img.shields.io/badge/Spring%20Boot-3.4.5-brightgreen.svg)](https://spring.io/projects/spring-boot)
[![Java](https://img.shields.io/badge/Java-21-orange.svg)](https://openjdk.java.net/)
[![React](https://img.shields.io/badge/React-Latest-blue.svg)](https://reactjs.org/)

## 🚀 Features

### Current MVP Features
- **Secure Authentication**
    - JWT-based authentication with access and refresh tokens
    - Role-based authorization (USER, ADMIN)
    - Email verification for account security

- **Media Management**
    - Upload and download various media types (images, videos, audio, documents)
    - Automatic metadata extraction using Apache Tika
    - Basic image optimization and resizing

- **Social Interaction**
    - Create and share posts with media attachments
    - Comment on posts
    - Like content
    - User profiles

### Upcoming Features
- **Advanced Media Processing**
    - Video transcoding with FFmpeg
    - Audio optimization
    - Multiple resolution options

- **Enhanced Social Features**
    - Follow/follower system
    - Direct messaging
    - Content discovery
    - Hashtags and trends

- **Cloud Integration**
    - Firebase/cloud storage support
    - Better scalability and performance

## 🛠️ Tech Stack

### Backend
- Java 21
- Spring Boot 3.4.5
- Spring Security with JWT
- Spring Data JPA
- PostgreSQL (production)
- H2 Database (testing)
- Apache Tika for metadata extraction
- Spring Mail for email services

### Frontend (In Development)
- React with TypeScript
- Tailwind CSS
- React Query for data fetching
- React Router for navigation

### DevOps & Tools
- Docker for containerization
- Maven for dependency management
- Log4j2 for comprehensive logging
- Git for version control

## 📋 Prerequisites

- JDK 21+
- Maven 3.8+
- PostgreSQL 14+
- Docker & Docker Compose (optional, for containerized setup)
- Node.js 20+ (for frontend development)

## 🔧 Setup & Installation

### Backend Setup

1. **Clone the repository**
   ```bash
   git clone https://github.com/Stephen-Salano/fileflow-api.git
   cd fileflow-api
   ```

2. **Configure application properties**

   Create an `application.yml` file in `src/main/resources/` with the following configuration:

   ```yaml
   spring:
     datasource:
       url: jdbc:postgresql://localhost:5432/fileflow
       username: your_username
       password: your_password
     jpa:
       hibernate:
         ddl-auto: update
       show-sql: true
     mail:
       host: smtp.youremailprovider.com
       port: 587
       username: your_email@example.com
       password: your_email_password
       properties:
         mail.smtp.auth: true
         mail.smtp.starttls.enable: true

   # JWT Configuration
   jwt:
     secret-key: your_jwt_secret_key_min_32_chars_long
     access-token-expiration: 900000  # 15 minutes in milliseconds
     refresh-token-expiration: 604800000  # 7 days in milliseconds

   # File Storage Configuration
   storage:
     location: file-uploads
     max-file-size: 5MB
   ```

3. **Build the application**
   ```bash
   mvn clean install
   ```

4. **Run the application**
   ```bash
   mvn spring-boot:run
   ```

   The API will be available at `http://localhost:8080`

### Docker Setup (Alternative)

1. **Build Docker image**
   ```bash
   docker build -t fileflow-api .
   ```

2. **Run with Docker Compose**
   ```bash
   docker-compose up
   ```

## 📁 Project Structure

```
Fileflow-API/
├── src/
│   ├── main/
│   │   ├── java/
│   │   │   └── com/stephensalano/fileflow_api/
│   │   │       ├── configs/                       # Configuration classes
│   │   │       │   ├── security/                  # Security-specific configurations
│   │   │       │   │   ├── JwtAuthFilter.java     # JWT authentication filter
│   │   │       │   │   ├── JwtService.java        # JWT token handling service
│   │   │       │   │   └── SecurityConfig.java    # Spring Security configuration
│   │   │       │   ├── AppConfig.java             # General application configuration
│   │   │       │   ├── AsyncConfig.java           # Async task execution configuration
│   │   │       │   ├── AuditingConfig.java        # JPA auditing configuration
│   │   │       │   ├── CorsConfig.java            # CORS configuration
│   │   │       │   ├── EmailConfig.java           # Email service configuration
│   │   │       │   ├── SecurityHeadersConfig.java # Security headers configuration
│   │   │       │   ├── StorageConfig.java         # File storage configuration
│   │   │       │   └── SwaggerConfig.java         # API documentation configuration
│   │   │       │
│   │   │       ├── controllers/                   # REST Controllers
│   │   │       │   ├── AuthController.java        # Authentication endpoints
│   │   │       │   ├── CommentController.java     # Comment management endpoints
│   │   │       │   ├── DeviceController.java      # Device fingerprint endpoints
│   │   │       │   ├── LikeController.java        # Like/reaction endpoints
│   │   │       │   ├── MediaController.java       # Media file handling endpoints
│   │   │       │   ├── PostController.java        # Social post endpoints
│   │   │       │   └── UserController.java        # User management endpoints
│   │   │       │
│   │   │       ├── dto/                           # Data Transfer Objects
│   │   │       │   ├── requests/                  # Request DTOs
│   │   │       │   │   ├── AuthRequest.java       # Authentication request
│   │   │       │   │   ├── CommentRequest.java    # Comment creation request
│   │   │       │   │   ├── DeviceFingerprintRequest.java # Device fingerprint data
│   │   │       │   │   ├── MediaUploadRequest.java # Media upload request
│   │   │       │   │   ├── PostRequest.java       # Post creation request
│   │   │       │   │   └── RegisterRequest.java   # User registration request
│   │   │       │   ├── responses/                 # Response DTOs
│   │   │       │   │   ├── AuthResponse.java      # Authentication response with tokens
│   │   │       │   │   ├── CommentResponse.java   # Comment data response
│   │   │       │   │   ├── DeviceFingerprintResponse.java # Device data response
│   │   │       │   │   ├── MediaResponse.java     # Media data response
│   │   │       │   │   ├── postResponse.java      # Post data response
│   │   │       │   │   └── UserResponse.java      # User data response
│   │   │       │   └── security/                  # Security-related DTOs
│   │   │       │
│   │   │       ├── entities/                      # JPA entities
│   │   │       │   ├── Account.java               # Account entity for auth credentials
│   │   │       │   ├── CollectionMedia.java       # Media collection item entity
│   │   │       │   ├── CollectionMediaId.java     # Composite key for collection media
│   │   │       │   ├── Comment.java               # Comment entity for post discussions
│   │   │       │   ├── DeviceFingerPrint.java     # Device fingerprint entity
│   │   │       │   ├── Follow.java                # Follow relationship entity
│   │   │       │   ├── FollowId.java              # Composite key for follow relationship
│   │   │       │   ├── Like.java                  # Like entity for content reactions
│   │   │       │   ├── Media.java                 # Media file metadata entity
│   │   │       │   ├── MediaCollection.java       # Media collection entity
│   │   │       │   ├── MediaTag.java              # Media tagging entity
│   │   │       │   ├── MediaVersion.java          # Media version history entity
│   │   │       │   ├── Post.java                  # Post entity for social content
│   │   │       │   ├── PostMedia.java             # Post-media relationship entity
│   │   │       │   ├── PostMediaId.java           # Composite key for post media
│   │   │       │   ├── ProcessingJob.java         # Media processing job entity
│   │   │       │   ├── RefreshToken.java          # JWT refresh token entity
│   │   │       │   ├── Role.java                  # User role enum (USER, ADMIN)
│   │   │       │   ├── TokenTypes.java            # Token type enumeration
│   │   │       │   ├── User.java                  # User entity with profile information
│   │   │       │   └── VerificationToken.java     # Email verification token entity
│   │   │       │
│   │   │       ├── events/                        # Event listeners and publishers
│   │   │       │   ├── MediaEventListener.java    # Media event listener
│   │   │       │   ├── MediaProcessingEvent.java  # Media processing event
│   │   │       │   ├── MediaUploadEvent.java      # Media upload event
│   │   │       │   ├── OnRegistrationCompleteEvent.java # Registration event
│   │   │       │   ├── OnWelcomeEvent.java        # Welcome email event
│   │   │       │   └── RegistrationListener.java  # Registration event listener
│   │   │       │
│   │   │       ├── exceptions/                    # Custom exceptions
│   │   │       │   ├── AccessDeniedException.java # Security access denied exception
│   │   │       │   ├── BadRequestException.java   # Invalid request exception
│   │   │       │   ├── GlobalExceptionHandler.java # Centralized exception handler
│   │   │       │   ├── ProcessingException.java   # Media processing exception
│   │   │       │   ├── ResourceNotFoundException.java # Entity not found exception
│   │   │       │   └── StorageException.java      # File storage exception
│   │   │       │
│   │   │       ├── models/                        # Non-entity model classes
│   │   │       │   ├── FileMetadata.java          # File metadata model
│   │   │       │   └── ProcessingOptions.java     # Processing options model
│   │   │       │
│   │   │       ├── repository/                    # Data repositories
│   │   │       │   ├── AccountRepository.java     # Account repository
│   │   │       │   ├── CommentRepository.java     # Comment repository
│   │   │       │   ├── DeviceFingerPrintRepository.java # Device fingerprint repository
│   │   │       │   ├── LikeRepository.java        # Like repository
│   │   │       │   ├── MediaRepository.java       # Media repository
│   │   │       │   ├── PostRepository.java        # Post repository
│   │   │       │   ├── RefreshTokenRepository.java # Refresh token repository
│   │   │       │   ├── UserRepository.java        # User repository
│   │   │       │   └── VerificationTokenRepository.java # Verification token repository
│   │   │       │
│   │   │       ├── services/                      # Service layer
│   │   │       │   ├── auth/                      # Authentication services
│   │   │       │   │   ├── AuthService.java       # Auth service interface
│   │   │       │   │   └── AuthServiceImpl.java   # Auth service implementation
│   │   │       │   ├── email/                     # Email services
│   │   │       │   │   ├── EmailService.java      # Email service interface
│   │   │       │   │   └── EmailServiceImpl.java  # Email service implementation
│   │   │       │   ├── media/                     # Media handling services
│   │   │       │   │   ├── CloudStorageServiceImpl.java # Cloud storage implementation
│   │   │       │   │   ├── FileStorageService.java # File storage service interface
│   │   │       │   │   ├── LocalStorageServiceImpl.java # Local storage implementation
│   │   │       │   │   ├── MediaService.java      # Media service interface
│   │   │       │   │   └── MediaServiceImpl.java  # Media service implementation
│   │   │       │   ├── processing/                # Media processing services
│   │   │       │   │   ├── FFmpegService.java     # FFmpeg service interface
│   │   │       │   │   ├── FFmpegServiceImpl.java # FFmpeg service implementation
│   │   │       │   │   ├── MetadataService.java   # Metadata extraction interface
│   │   │       │   │   └── TikaMetadataServiceImpl.java # Apache Tika implementation
│   │   │       │   ├── security/                  # Security services
│   │   │       │   │   ├── DeviceFingerprintService.java # Device service interface
│   │   │       │   │   └── DeviceFingerprintServiceImpl.java # Device service implementation
│   │   │       │   ├── social/                    # Social feature services
│   │   │       │   │   ├── CommentService.java    # Comment service interface
│   │   │       │   │   ├── CommentServiceImpl.java # Comment service implementation
│   │   │       │   │   ├── LikeService.java       # Like service interface
│   │   │       │   │   ├── LikeServiceImpl.java   # Like service implementation
│   │   │       │   │   ├── PostService.java       # Post service interface
│   │   │       │   │   └── PostServiceImpl.java   # Post service implementation
│   │   │       │   ├── user/                      # User-related services
│   │   │       │   │   ├── AccountDetailsService.java # UserDetails service
│   │   │       │   │   ├── UserService.java       # User service interface
│   │   │       │   │   └── UserServiceImpl.java   # User service implementation
│   │   │       │   └── verification_token/        # Token verification services
│   │   │       │       ├── VerificationTokenService.java # Token service interface
│   │   │       │       └── VerificationTokenServiceImpl.java # Token service implementation
│   │   │       │
│   │   │       ├── utils/                         # Utility classes
│   │   │       │   ├── FileUtils.java             # File handling utilities
│   │   │       │   ├── SecurityUtils.java         # Security-related utilities
│   │   │       │   └── ValidationUtils.java       # Input validation utilities
│   │   │       │
│   │   │       └── FileflowApiApplication.java    # Main application class
│   │   │
│   │   └── resources/
│   │       ├── templates.email/                   # Email template files
│   │       │   ├── verification-email.html        # Email verification template
│   │       │   └── welcome-email.html             # Welcome email template
│   │       ├── application.yml                    # Base application configuration
│   │       ├── application-dev.yml                # Development environment config
│   │       ├── application-prod.yml               # Production environment config
│   │       └── application-test.yml               # Testing environment config
│   │
│   └── test/
│       └── java/
│           └── com/stephensalano/fileflow_api/
│               ├── controllers/                   # Controller tests
│               │   ├── integration_tests/         # Integration tests
│               │   │   ├── AuthControllerHappyPathRegistrationTest.java
│               │   │   ├── AuthControllerHealthIntegrationTest.java
│               │   │   └── AuthControllerInvalidRegistrationIntegrationTest.java
│               │   └── unit_tests/                # Unit tests
│               │       ├── AuthControllerLoginUnitTest.java
│               │       └── AuthControllerRegisterUnitTest.java
│               ├── security/                      # Security tests
│               └── FileflowApiApplicationTests.java # Main application tests
│
├── .gitattributes                 # Git attributes configuration
├── .gitignore                     # Git ignore configuration
├── compose.yaml                   # Docker Compose configuration
├── LICENSE                        # MIT License file
├── mvnw                           # Maven wrapper script (Unix)
├── mvnw.cmd                       # Maven wrapper script (Windows)
├── pom.xml                        # Maven project configuration
└── README.MD                      # Project documentation
```

## 🔒 API Endpoints
- `POST /api/v1/auth/register` - Register a new user
- `POST /api/v1/auth/authenticate` - Login and get JWT tokens
- `POST /api/v1/auth/refresh-token` - Refresh access token
- `POST /api/v1/auth/logout` - Logout user (invalidate tokens)
- `GET /api/v1/auth/verify` - Verify email with token

### User Endpoints
- `GET /api/v1/users/me` - Get current user profile
- `PUT /api/v1/users/me` - Update user profile
- `PUT /api/v1/users/password` - Change password

### Media Endpoints
- `POST /api/v1/media` - Upload media file
- `GET /api/v1/media` - Get user's media files
- `GET /api/v1/media/{id}` - Get specific media file metadata
- `GET /api/v1/media/file/{id}` - Download media file
- `DELETE /api/v1/media/{id}` - Delete media file

### Social Endpoints
- `POST /api/v1/posts` - Create new post
- `GET /api/v1/posts` - Get feed posts
- `GET /api/v1/posts/{id}` - Get specific post
- `PUT /api/v1/posts/{id}` - Update post
- `DELETE /api/v1/posts/{id}` - Delete post
- `POST /api/v1/posts/{id}/comments` - Add comment to post
- `GET /api/v1/posts/{id}/comments` - Get post comments
- `POST /api/v1/posts/{id}/likes` - Like a post
- `DELETE /api/v1/posts/{id}/likes` - Unlike a post

## 📊 Development Roadmap

### Phase 1: MVP (Current)
- Authentication system
- Basic file upload/download
- Simple image optimization
- Core social features

### Phase 2: Enhanced Media Processing
- Video processing with FFmpeg
- Audio optimization
- Multiple resolution options
- Advanced metadata extraction

### Phase 3: Advanced Social Features
- Follow/follower system
- Direct messaging
- Content discovery algorithms
- Notifications system

### Phase 4: Cloud Integration & Scaling
- Firebase/Cloud storage integration
- Performance optimizations
- Analytics and monitoring
- Mobile responsive frontend

## 🧪 Testing

Run tests with Maven:

```bash
# Run all tests
mvn test

# Run specific test class
mvn test -Dtest=AuthServiceTest

# Run with coverage report
mvn test jacoco:report
```

## 🤝 Contributing

Contributions are welcome! To contribute:

1. Fork the repository
2. Create your feature branch: `git checkout -b feature/amazing-feature`
3. Commit your changes: `git commit -m 'Add some amazing feature'`
4. Push to the branch: `git push origin feature/amazing-feature`
5. Open a Pull Request

Please make sure to update tests as appropriate.

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 📬 Contact

LinkedIn - [Stephen Salano](www.linkedin.com/in/stephen-salano)

Project Link: [https://github.com/Stephen-Salano/fileflow-api](https://github.com/Stephen-Salano/fileflow-api)