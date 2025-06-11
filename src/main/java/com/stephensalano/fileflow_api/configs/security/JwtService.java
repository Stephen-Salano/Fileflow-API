package com.stephensalano.fileflow_api.configs.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.AeadAlgorithm;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SecretKeyAlgorithm;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.env.Environment;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

/**
 * Service for handling JWT operations
 *
 * This service provides core functionality for:
 * - Generating access and refresh tokens
 * - Validating tokens and checking expiration
 * - Extracting user info from tokens
 * - Managing token lifecycle
 *
 * Uses JJWT library for token operations and Spring's configuration properties
 * for secure settings like secret keys and expiration times
 */
@Service
@Slf4j
@RequiredArgsConstructor
public class JwtService {

    private final Environment environment;

    // Injecting JWT configuration from application.yaml
    @Value("${jwt.secret-key}") // Used for JWS signing (integrity)
    private String secretKey;

    // Injecting JWE encryption key
    @Value("${jwt.encryption-key}")
    private String encryptionKey;

    @Getter
    @Value("${jwt.access-token-expiration}")
    private long accessTokenExpiration;

    @Getter
    @Value("${jwt.refresh-token-expiration}")
    private long refreshTokenExpiration;

    @Value("${spring.application.name}")
    private String applicationName;

    // Using A256GCM for content encryption (AES 256-bit GCM)
    // Using A256KW for key management (AES 256-bit Key Wrap)
    private static final AeadAlgorithm ENCRYPTION_ALGORITHM = Jwts.ENC.A256GCM;
    private static final SecretKeyAlgorithm KEY_MANAGEMENT_ALGORITHM = Jwts.KEY.A256KW;

    // constants for minimal token claims
    private static final String ENVIRONMENT_CLAIM = "env";
    private static final String TOKEN_TYPE_CLAIM = "typ";

    /**
     * Generates an access token for the authenticated user
     * Access tokens have shorter expiration times and are used for API requests
     *
     * @param userDetails the authenticated user's details
     * @return JWT access token string
     */
    public String generateAccessToken(UserDetails userDetails) {
        log.debug("Generating access token for user: {}", userDetails.getUsername());
        Map<String, Object> claims = new HashMap<>();
        claims.put(TOKEN_TYPE_CLAIM, "access");
        return generateToken(claims, userDetails, accessTokenExpiration);
    }

    /**
     * Generates a refresh token for the authenticated user
     * Refresh tokens have longer expiration times and are used to get new access tokens
     *
     * @param userDetails The authenticated user's details
     * @return JWT refresh token String
     */
    public String generateRefreshToken(UserDetails userDetails) {
        log.debug("Generating refresh token for user: {}", userDetails.getUsername());
        Map<String, Object> claims = new HashMap<>();
        claims.put(TOKEN_TYPE_CLAIM, "refresh");
        return generateToken(claims, userDetails, refreshTokenExpiration);
    }

    /**
     * Generates a JWT token with custom claims and expiration
     * This is the core token generation method used by both access and refresh tokens
     * Uses JWE encryption to prevent token debugging
     *
     * @param extraClaims additional claims to include in the token
     * @param userDetails user details for the token subject
     * @param expiration token expiration time in milliseconds
     * @return JWT token String
     */
    private String generateToken(Map<String, Object> extraClaims, UserDetails userDetails, long expiration) {
        String currentEnvironment = getCurrentEnvironment();
        String issuer = applicationName + "_" + currentEnvironment;

        long nowMillis = System.currentTimeMillis();
        Date now = new Date(nowMillis);
        Date expiryDate = new Date(nowMillis + expiration);

        return Jwts.builder()
                // Add custom claims
                .claims(extraClaims)
                // Set standard claims
                .subject(userDetails.getUsername())
                // set the issuer of tokens
                .issuer(issuer)
                .issuedAt(now)
                .expiration(expiryDate)
                // Add environment claim
                .claim(ENVIRONMENT_CLAIM, currentEnvironment)
                // Encrypt the token (JWE) - prevents debugging
                .encryptWith(getEncryptionKey(), KEY_MANAGEMENT_ALGORITHM, ENCRYPTION_ALGORITHM)
                .compact();
    }

    /**
     * Extracts the username (subject) from a JWT token
     *
     * @param token JWT token string
     * @return Username extracted from token
     */
    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    /**
     * Generic method to extract any claim from a JWT token
     * Uses a function to specify which claim to extract
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
     * Validates a JWT token against user details
     * First decrypts the token, then checks if it belongs to the user and hasn't expired
     *
     * @param token JWT token string
     * @param userDetails User details to validate against
     * @return true if token is valid, false otherwise
     */
    public boolean isTokenValid(String token, UserDetails userDetails) {
        try {
            // First attempt to decrypt and extract claims - if this fails, token is invalid
            final String username = extractUsername(token);
            if (username == null) {
                log.warn("Failed to extract username from token - decryption may have failed");
                return false;
            }

            boolean isUsernameValid = username.equals(userDetails.getUsername());
            boolean isTokenNotExpired = !isTokenExpired(token);
            boolean isIssuerValid = isIssuerValid(token);
            boolean isEnvironmentValid = isEnvironmentValid(token);

            log.debug("Token validation for user {}: username_valid={}, not_expired={}, issuer_valid={}, env_valid={}",
                    username, isUsernameValid, isTokenNotExpired, isIssuerValid, isEnvironmentValid);
            return isUsernameValid && isTokenNotExpired && isIssuerValid && isEnvironmentValid;
        } catch (Exception e) {
            log.warn("Token validation failed (likely decryption error): {}", e.getMessage());
            return false;
        }
    }

    private boolean isIssuerValid(String token) {
        try {
            String tokenIssuer = extractClaim(token, Claims::getIssuer);
            String currentEnvironment = getCurrentEnvironment();
            String expectedIssuer = applicationName + "_" + currentEnvironment;

            boolean valid = expectedIssuer.equals(tokenIssuer);
            log.debug("Issuer validation: expected={}, actual={}, valid={}", expectedIssuer, tokenIssuer, valid);
            return valid;
        } catch (Exception e) {
            log.warn("Error validating issuer: {}", e.getMessage());
            return false;
        }
    }

    private boolean isEnvironmentValid(String token) {
        try {
            String tokenEnvironment = extractClaim(token, claims -> claims.get(ENVIRONMENT_CLAIM, String.class));
            String currentEnvironment = getCurrentEnvironment();

            boolean valid = currentEnvironment.equals(tokenEnvironment);
            log.debug("Environment validation: expected={}, actual={}, valid={}", currentEnvironment, tokenEnvironment, valid);
            return valid;
        } catch (Exception e) {
            log.warn("Error validating environment: {}", e.getMessage());
            return false;
        }
    }

    private String getCurrentEnvironment() {
        String[] activeProfiles = environment.getActiveProfiles();
        if (activeProfiles.length > 0) {
            return Arrays.stream(activeProfiles)
                    .filter(profile -> profile.equals("dev") || profile.equals("prod") || profile.equals("test"))
                    .findFirst()
                    .orElse("default");
        }
        return "default";
    }

    /**
     * Checks if a JWT token has expired
     *
     * @param token JWT token string
     * @return true if token is expired, false otherwise
     */
    private boolean isTokenExpired(String token) {
        try {
            Date expiration = extractExpiration(token);
            boolean expired = expiration.before(new Date());
            log.debug("token expiration check: expires_at={}, is_expired={}", expiration, expired);
            return expired;
        } catch (Exception e) {
            log.warn("Error checking token expiration: {}", e.getMessage());
            return true;
        }
    }

    /**
     * Extracts the expiration date from a JWT token
     *
     * @param token JWT token string
     * @return Expiration date of the token
     */
    private Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    /**
     * Extracts all claims from a JWT token
     * This method decrypts JWE tokens and extracts claims
     * If decryption fails, this will throw an exception
     *
     * @param token JWT token String
     * @return claims object containing all token claims
     * @throws RuntimeException if token cannot be decrypted or parsed
     */
    private Claims extractAllClaims(String token) {
        try {
            return Jwts.parser()
                    .decryptWith(getEncryptionKey())
                    .build()
                    .parseEncryptedClaims(token)
                    .getPayload();
        } catch (Exception e) {
            log.error("Failed to decrypt/parse token: {}", e.getMessage());
            throw new RuntimeException("Invalid or corrupted token", e);
        }
    }

    /**
     * Creates the signing key from the secret key string
     * Uses HMAC-SHA256 algorithm for token signing
     *
     * @return SecretKey object for signing/verifying tokens
     */
    private SecretKey getSignInKey() {
        byte[] keyBytes = Decoders.BASE64.decode(secretKey);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    /**
     * Creates the encryption key for JWE operations
     * Uses the configured encryption key for token encryption/decryption
     *
     * @return SecretKey object for encryption/decryption
     */
    private SecretKey getEncryptionKey() {
        byte[] keyBytes = Decoders.BASE64.decode(encryptionKey);
        return Keys.hmacShaKeyFor(keyBytes);
    }
}