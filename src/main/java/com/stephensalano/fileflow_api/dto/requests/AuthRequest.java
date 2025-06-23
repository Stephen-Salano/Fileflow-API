package com.stephensalano.fileflow_api.dto.requests;

import jakarta.validation.constraints.NotBlank;

/**
 * Data Transfer Object for user authentication/login requests
 *
 * This record captures the essential information needed for user login:
 * - Username or email for identification
 * - Password for authentication
 *
 * Using a record provides:
 * - Immutable data structure
 * - Automatic equals(), hashCode(), and toString() methods
 * - Compact syntax with validation annotations
 *
 * Bean validation ensures that both fields are provided and not empty.
 */
public record AuthRequest(
        @NotBlank(message = "Username or email cannot be blank")
        String usernameOrEmail,

        @NotBlank(message = "Password cannot be blank")
        String password,
        String fingerprintHash
) {
}
