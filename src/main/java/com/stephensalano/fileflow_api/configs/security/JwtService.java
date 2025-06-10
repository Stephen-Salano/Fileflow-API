package com.stephensalano.fileflow_api.configs.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.env.Environment;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Arrays;
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
@RequiredArgsConstructor
public class JwtService {

    private final Environment environment;

    // Injecting JWT configuration from application.yaml
    @Value("${jwt.secret-key}")
    private String secretKey;

    @Getter
    @Value("${jwt.access-token-expiration}")
    private long accessTokenExpiration;

    @Getter
    @Value("${jwt.refresh-token-expiration}")
    private long refreshTokenExpiration;

    @Value("${spring.application.name}")
    private String applicationName;

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
    public String generateAccessToken(UserDetails userDetails){
        log.debug("Generating access token for user: {}", userDetails.getUsername());
        Map<String, Object> claims = new HashMap<>();
        claims.put(TOKEN_TYPE_CLAIM, "access");
        return generateToken(claims, userDetails, accessTokenExpiration);
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
        Map<String, Object> claims = new HashMap<>();
        claims.put(TOKEN_TYPE_CLAIM, "refresh");
        return generateToken(claims, userDetails, refreshTokenExpiration);
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
        String currentEnvironment = getCurrentEnvironment();
        String issuer = applicationName + "_" + currentEnvironment;

        return Jwts.builder()
                // Add any extra claims (like roles, permissions, etc.)
                .setClaims(extraClaims)
                // Set the subject (username) of the token
                .setSubject(userDetails.getUsername())
                // who issued the tokens
                .setIssuer(issuer)
                .claim(ENVIRONMENT_CLAIM, currentEnvironment)
                // Set when the token was issued
                .setIssuedAt(new Date(System.currentTimeMillis()))
                // Set en the token expires
                .setExpiration(new Date(System.currentTimeMillis() + expiration))
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
            boolean isIssuerValid = isIssuerValid(token);
            boolean isEnvironmentValid = isEnvironmentValid(token);

            log.debug("Token validation for user {}: username_valid={}, not_expired={}, issuer_valid={}, env_valid={}",
                    username, isUsernameValid, isTokenNotExpired, isIssuerValid, isEnvironmentValid);
            return isUsernameValid && isTokenNotExpired && isIssuerValid && isEnvironmentValid;
        } catch (Exception e){
            log.warn("Token validation failed: {}", e.getMessage());
            return false;
        }
    }

    private boolean isIssuerValid(String token) {
        try{
            String tokenIssuer = extractClaim(token, Claims::getIssuer);
            String currentEnvironment = getCurrentEnvironment();
            String expectedIssuer = applicationName + "_" + currentEnvironment;

            boolean valid = expectedIssuer.equals(tokenIssuer);
            log.debug("Issuer validation: expected={}, actual={}, valid={}", expectedIssuer, tokenIssuer, valid);
            return valid;
        } catch (Exception e){
            log.warn("Error validating issuer: {}", e.getMessage());
            return false;
        }
    }

    private boolean isEnvironmentValid(String token) {
        try{
            String tokenEnvironment = extractClaim(token, claims -> claims.get(ENVIRONMENT_CLAIM, String.class));
            String currentEnvironment = getCurrentEnvironment();

            boolean valid = currentEnvironment.equals(tokenEnvironment);
            log.debug("Environment validation: expected={}, actual={}, valid={}", currentEnvironment, tokenEnvironment, valid);
            return valid;
        }catch (Exception e){
            log.warn("Error validating environment: {}", e.getMessage());
            return false;
        }
    }

    private String getCurrentEnvironment() {
        String[] activeProfiles = environment.getActiveProfiles();
        if (activeProfiles.length > 0){
            return Arrays.stream(activeProfiles)
                    .filter(profile -> profile.equals("dev") || profile.equals("prod") || profile.equals("test"))
                    .findFirst()
                    .orElse("default");
        }
        return "default";

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
    public Key getSignInKey() {
        // Decode the base64-encoded secret key
        byte[] keyBytes = Decoders.BASE64.decode(secretKey);
        // Create HMAC key for HS256 algorithm
        return Keys.hmacShaKeyFor(keyBytes);
    }

}
