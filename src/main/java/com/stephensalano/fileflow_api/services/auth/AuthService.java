package com.stephensalano.fileflow_api.services.auth;

import com.stephensalano.fileflow_api.dto.requests.RegisterRequest;
import com.stephensalano.fileflow_api.entities.Account;

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

}
