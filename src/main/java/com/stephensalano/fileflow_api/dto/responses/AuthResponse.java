package com.stephensalano.fileflow_api.dto.responses;

import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Data Transfer Object for authentication responses
 *
 * This record contains the authentication tokens and user information
 * returned after successful login:
 * - Access token for API requests
 * - Refresh token for obtaining new access tokens
 * - Token type (typically "Bearer")
 * - Expiration information
 * - Basic user information
 *
 * The response follows JWT/OAuth2 standards with proper JSON property naming.
 */
public record AuthResponse(
        @JsonProperty("access_token")
        String accessToken,

        @JsonProperty("refresh_token")
        String refreshToken,

        @JsonProperty("token_type")
        String tokenType,

        @JsonProperty("expires_in")
        long expiresIn,

        String username,
        String email,
        String role
) {
    /**
     * Static factory method to create AuthResponse with Bearer token type
     *
     * @param accessToken JWT access token
     * @param refreshToken JWT refresh token
     * @param expiresIn Expiration time in seconds
     * @param username User's username
     * @param email User's email
     * @param role User's role
     * @return AuthResponse with all authentication details
     */
    public static AuthResponse of(String accessToken, String refreshToken, long expiresIn,
                                  String username, String email, String role){
        return new AuthResponse(
                accessToken, refreshToken, "Bearer ", expiresIn, username,
                email, role
        );

    }
}
