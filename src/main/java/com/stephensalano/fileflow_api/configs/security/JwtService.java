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
import javax.crypto.spec.SecretKeySpec;
import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Service
@Slf4j
@RequiredArgsConstructor
public class JwtService {

    private final Environment environment;

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

    private static final AeadAlgorithm ENCRYPTION_ALGORITHM = Jwts.ENC.A256GCM;
    private static final SecretKeyAlgorithm KEY_MANAGEMENT_ALGORITHM = Jwts.KEY.A256KW;
    private static final String ENVIRONMENT_CLAIM = "env";
    private static final String TOKEN_TYPE_CLAIM = "typ";

    public String generateAccessToken(UserDetails userDetails) {
        log.debug("Generating access token for user: {}", userDetails.getUsername());
        Map<String, Object> claims = new HashMap<>();
        claims.put(TOKEN_TYPE_CLAIM, "access");
        return generateToken(claims, userDetails, accessTokenExpiration);
    }

    public String generateRefreshToken(UserDetails userDetails) {
        log.debug("Generating refresh token for user: {}", userDetails.getUsername());
        Map<String, Object> claims = new HashMap<>();
        claims.put(TOKEN_TYPE_CLAIM, "refresh");
        return generateToken(claims, userDetails, refreshTokenExpiration);
    }

    private String generateToken(Map<String, Object> extraClaims, UserDetails userDetails, long expiration) {
        String currentEnvironment = getCurrentEnvironment();
        String issuer = applicationName + "_" + currentEnvironment;

        long nowMillis = System.currentTimeMillis();
        Date now = new Date(nowMillis);
        Date expiryDate = new Date(nowMillis + expiration);

        return Jwts.builder()
                .claims(extraClaims)
                .subject(userDetails.getUsername())
                .issuer(issuer)
                .issuedAt(now)
                .expiration(expiryDate)
                .claim(ENVIRONMENT_CLAIM, currentEnvironment)
                .encryptWith(getEncryptionKey(), KEY_MANAGEMENT_ALGORITHM, ENCRYPTION_ALGORITHM)
                .compact();
    }

    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    private <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    public boolean isTokenValid(String token, UserDetails userDetails) {
        try {
            final String username = extractUsername(token);
            if (username == null) {
                log.warn("Failed to extract username from token");
                return false;
            }

            // Consolidated validation - all checks in one place
            boolean isUsernameValid = username.equals(userDetails.getUsername());
            boolean isTokenNotExpired = !isTokenExpired(token);
            boolean isSecurityValid = validateTokenSecurity(token);

            log.debug("Token validation for user {}: username_valid={}, not_expired={}, security_valid={}",
                    username, isUsernameValid, isTokenNotExpired, isSecurityValid);

            return isUsernameValid && isTokenNotExpired && isSecurityValid;
        } catch (Exception e) {
            log.warn("Token validation failed: {}", e.getMessage());
            return false;
        }
    }

    /**
     * Consolidated security validation method
     * Checks issuer, environment, and token structure
     */
    private boolean validateTokenSecurity(String token) {
        try {
            Claims claims = extractAllClaims(token);

            return validateIssuer(claims) &&
                    validateEnvironment(claims) &&
                    validateTokenStructure(claims);
        } catch (Exception e) {
            log.warn("Security validation failed: {}", e.getMessage());
            return false;
        }
    }

    private boolean validateIssuer(Claims claims) {
        String tokenIssuer = claims.getIssuer();
        String expectedIssuer = applicationName + "_" + getCurrentEnvironment();

        boolean valid = expectedIssuer.equals(tokenIssuer);
        if (!valid) {
            log.warn("Invalid issuer: expected={}, actual={}", expectedIssuer, tokenIssuer);
        }
        return valid;
    }

    private boolean validateEnvironment(Claims claims) {
        String tokenEnvironment = claims.get(ENVIRONMENT_CLAIM, String.class);
        String currentEnvironment = getCurrentEnvironment();

        boolean valid = currentEnvironment.equals(tokenEnvironment);
        if (!valid) {
            log.warn("Environment mismatch: expected={}, actual={}", currentEnvironment, tokenEnvironment);
        }
        return valid;
    }

    private boolean validateTokenStructure(Claims claims) {
        return claims.getSubject() != null &&
                claims.getIssuer() != null &&
                claims.get(ENVIRONMENT_CLAIM) != null &&
                claims.get(TOKEN_TYPE_CLAIM) != null;
    }

    private boolean isTokenExpired(String token) {
        try {
            Date expiration = extractExpiration(token);
            boolean expired = expiration.before(new Date());
            log.debug("Token expiration check: expires_at={}, is_expired={}", expiration, expired);
            return expired;
        } catch (Exception e) {
            log.warn("Error checking token expiration: {}", e.getMessage());
            return true;
        }
    }

    private Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

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

    private String getCurrentEnvironment() {
        String[] activeProfiles = environment.getActiveProfiles();
        return Arrays.stream(activeProfiles)
                .filter(profile -> profile.matches("dev|prod|test"))
                .findFirst()
                .orElse("default");
    }

    private SecretKey getEncryptionKey() {
        byte[] keyBytes = Decoders.BASE64.decode(encryptionKey);
        return new SecretKeySpec(keyBytes, "AES");
    }

    /**
     * Safe method to extract token metadata for logging
     */
    public String getTokenMetadata(String token) {
        try {
            Claims claims = extractAllClaims(token);
            return String.format("issuer=%s, env=%s, type=%s, exp=%s",
                    claims.getIssuer(),
                    claims.get(ENVIRONMENT_CLAIM),
                    claims.get(TOKEN_TYPE_CLAIM),
                    claims.getExpiration());
        } catch (Exception e) {
            return "invalid_token";
        }
    }
}