package com.stephensalano.fileflow_api.configs.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;


/**Service for handling JWT operations
 *
 * This service provides core functionality  for:
 * - Generating access and refresh tokens
 * - Validating tokens and checking expiration
 * - Extracting user info from tokens
 * - Managing token lifecycle
 *
 * Uses JJWT library for token operations and Spring's configuration properties
 * for secure settings like secret keys and expirations times
 */
@Service
@Slf4j
public class JwtService {

    // Injecting JWT configuration from application.yaml
    @Value("${jwt.secret-key}")
    private String secretKey;

    @Getter
    @Value("${jwt.access-token-expiration}")
    private long accessTokenExpiration;

    @Getter
    @Value("${jwt.refresh-token-expiration}")
    private long refreshTokenExpiration;

    /**
     * Generates an access token for the authenticated user
     * Access tokens have shorter expiration times and are used for API requests
     *
     * @param userDetails the authenticated user's details
     * @return JWT access token string
     */
    public String generateAccessToken(UserDetails userDetails){
        log.debug("Generating access token for user: {}", userDetails.getUsername());
        return generateToken(new HashMap<>(), userDetails, accessTokenExpiration);
    }

    /**
     * Generates a refresh token for  the authenticated user
     * Refresh tokens have longer expirations times and are used to get new access tokens
     *
     * @param userDetails The authenticated user's details
     * @return JWT refresh token String
     */
    public String generateRefreshToken(UserDetails userDetails){
        log.debug("Generating refresh token for user: {}", userDetails.getUsername());
        return generateToken(new HashMap<>(), userDetails, refreshTokenExpiration);
    }


    /**
     * Generates a JWT token with custom claims and expiration
     * This is the core token generation method used by both access and refresh tokens
     *
     * @param extraClaims additional claims to include in the token
     * @param userDetails user details for the token subject
     * @param expiration token expirations time in milliseconds
     * @return JWT token String
     */
    private String generateToken(Map<String, Object> extraClaims, UserDetails userDetails, long expiration) {
        return Jwts.builder()
                // Add any extra claims (like roles, permissions, etc.)
                .setClaims(extraClaims)
                // Set the subject (username) of the token
                .setSubject(userDetails.getUsername())
                // Set when the token was issued
                .setIssuedAt(new Date(System.currentTimeMillis()))
                // Set en the token expires
                .setExpiration(new Date(System.currentTimeMillis()))
                // Sign the token with our secret key
                .signWith(getSignInKey(), SignatureAlgorithm.HS256)
                // Build the final token string
                .compact();
    }

    /**
     * <p>Extracts the username (subject) from a JWT token</p>
     *
     * @param token JWT token string
     * @return Username extracted from token
     */
    public String extractUsername(String token){
        return extractClaim(token, Claims::getSubject);
    }

    /**
     * <p>Generic method to extract any claim from a JWT token</p>
     * <p>Uses a function to specify which claim to extract</p>
     *
     * @param token JWT token string
     * @param claimsResolver Function that specifies which claim to extract
     * @return The extracted claim value
     * @param <T> Type of claim being extracted
     */
    private <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    /**
     * <p>Validates a JWT token against user details</p>
     * <p>Checks if the token belongs to the user and hasn't expired</p>
     *
     * @param token JWT token string
     * @param userDetails User details to validate against
     * @return true if token is valid, false otherwise
     */
    public boolean isTokenValid(String token, UserDetails userDetails){
        try{
            final String username = extractUsername(token);
            boolean isUsernameValid = username.equals(userDetails.getUsername());
            boolean isTokenNotExpired = !isTokenExpired(token);

            log.debug("Token validation for user {}: username_valid={}, not_expired={}", username, isUsernameValid, isTokenNotExpired);
            return isUsernameValid && isTokenNotExpired;
        } catch (Exception e){
            log.warn("Token validation failed: {}", e.getMessage());
            return false;
        }
    }

    /**
     * <p>Checks if a JWT token has expired</p>
     *
     *
     * @param token JWT token string
     * @return true if token is expired, false otherwise
     */
    private boolean isTokenExpired(String token) {
        try{
            Date expiration = extractExpiration(token);
            boolean expired = expiration.before(new Date());
            log.debug("token expiration check: expires_at={}, is_expired={}", expiration, expired);
            return expired;
        } catch (Exception e){
            log.warn("Error checking token expiration: {}", e.getMessage());
            return true;
        }
    }

    /**
     * Extracts the expiration date from a JWt token
     *
     * @param token JWT token string
     * @return Expiration date of the token
     */
    private Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }


    /**
     * <p> Extracts all claims from a JWT token</p>
     * This is the core method that parses and validates the token signature
     *
     * @param token JWT token String
     * @return claims object containing all token claims
     */
    private Claims extractAllClaims(String token) {
        return Jwts.parserBuilder()
                // Set the key used to verify the token signature
                .setSigningKey(getSignInKey())
                // Build the parser
                .build()
                // Parse the token and extract claims
                .parseClaimsJws(token)
                .getBody();
    }

    /**
     * <p>Creates the signing key from the secret key string</p>
     * <p>Uses HMAC-SHA256 algorithm for token signing</p>
     *
     * @return key object for signing/verifying tokens
     */
    private Key getSignInKey() {
        // Decode the base64-encoded secret key
        byte[] keyBytes = Decoders.BASE64.decode(secretKey);
        // Create HMAC key for HS256 algorithm
        return Keys.hmacShaKeyFor(keyBytes);
    }

}
