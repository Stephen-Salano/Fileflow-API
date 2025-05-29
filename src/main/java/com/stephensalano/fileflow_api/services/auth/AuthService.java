package com.stephensalano.fileflow_api.services.auth;

import com.stephensalano.fileflow_api.dto.requests.AuthRequest;
import com.stephensalano.fileflow_api.dto.requests.RegisterRequest;
import com.stephensalano.fileflow_api.dto.responses.AuthResponse;
import com.stephensalano.fileflow_api.entities.Account;
import org.springframework.security.core.Authentication;

/**
 * Service responsible for authentication-related operations including
 * user registration, verification, and login
 */
public interface AuthService {

    /**
     * Registers a new user in the system
     * This process includes:
     * 1. Validating the registration data
     * 2. Creating User and Account entities
     * 3. Generating a verification token
     * 4. Sending a verification email
     *
     * @param request the registration request data provided by the user
     * @return The newly created Account entity
     * @throws IllegalArgumentException if the registration data is invalid
     * @throws RuntimeException if there is an error during registration
     */
    Account registerUser(RegisterRequest request);

    /**
     * Verifies a user's email using a token sent during registration
     *
     * @param token The verification token
     * @return true if verification was successful, false otherwise
     * @throws IllegalArgumentException if the token is invalid or expired
     */
    boolean verifyEmail(String token);

    /**
     * Authenticates a user and returns JWT tokens
     *
     * @param authRequest the login credentials
     * @return AuthResponse containing access and refresh tokens
     */
    AuthResponse login(AuthRequest authRequest);

    /**
     * Logs out a user by invalidating their refresh tokens
     * @param authentication The current user's authentication
     */
    void logout(Authentication authentication);

    /**
     * Refreshes an access token using a valid refresh token
     *
     * @param refreshToken the refresh token
     * @return AuthResponse with new tokens
     */
    AuthResponse refreshToken(String refreshToken);
}
