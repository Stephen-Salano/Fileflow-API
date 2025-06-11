package com.stephensalano.fileflow_api.configs.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.util.Arrays;

@Component
@RequiredArgsConstructor
@Slf4j
public class TokenSecurityValidator {

    private final Environment environment;

    @Value("${jwt.encryption-key}")
    private String encryptionKey;

    @Value("${spring.application.name}")
    private String applicationName;

    /**
     * Validates token security by decrypting and checking claims
     *
     * @param token encrypted JWT token
     * @return true if token passes all security validations
     */
    public boolean validateTokenSecurity(String token) {
        try {
            Claims claims = extractClaims(token);

            return validateIssuer(claims) && validateEnvironment(claims) && validateTokenStructure(claims);

        } catch (Exception e) {
            log.warn("Token security validation failed (decryption error): {}", e.getMessage());
            return false;
        }
    }

    /**
     * Extracts claims from encrypted JWT token
     * This method decrypts the token first, then extracts claims
     *
     * @param token encrypted JWT token
     * @return decrypted claims
     * @throws RuntimeException if decryption fails
     */
    private Claims extractClaims(String token) {
        try {
            return Jwts.parser()
                    .decryptWith(getEncryptionKey())
                    .build()
                    .parseEncryptedClaims(token)
                    .getPayload();
        } catch (Exception e) {
            log.error("Failed to decrypt token for security validation: {}", e.getMessage());
            throw new RuntimeException("Token decryption failed", e);
        }
    }

    /**
     * Validates the token issuer after decryption
     *
     * @param claims decrypted token claims
     * @return true if issuer is valid
     */
    private boolean validateIssuer(Claims claims) {
        String issuer = claims.getIssuer();
        String expectedIssuer = applicationName + "_" + getCurrentEnvironment();

        boolean valid = expectedIssuer.equals(issuer);
        if (!valid) {
            log.warn("Invalid issuer: expected={}, actual={}", expectedIssuer, issuer);
        }
        return valid;
    }

    /**
     * Validates the environment claim after decryption
     *
     * @param claims decrypted token claims
     * @return true if environment matches
     */
    private boolean validateEnvironment(Claims claims) {
        String tokenEnv = (String) claims.get("env");
        String currentEnv = getCurrentEnvironment();

        boolean valid = currentEnv.equals(tokenEnv);
        if (!valid) {
            log.warn("Environment mismatch: current={}, token={}", currentEnv, tokenEnv);
        }
        return valid;
    }

    /**
     * Validates token structure after decryption
     * Ensures all required claims are present
     *
     * @param claims decrypted token claims
     * @return true if all required claims are present
     */
    private boolean validateTokenStructure(Claims claims) {
        // Ensure minimal required claims are present
        return claims.getSubject() != null &&
                claims.getIssuer() != null &&
                claims.get("env") != null &&
                claims.get("typ") != null;
    }

    private String getCurrentEnvironment() {
        String[] activeProfiles = environment.getActiveProfiles();
        return Arrays.stream(activeProfiles)
                .filter(profile -> profile.matches("dev|prod|test"))
                .findFirst()
                .orElse("default");
    }

    /**
     * Creates the encryption key for JWE operations
     *
     * @return SecretKey for token decryption
     */
    private SecretKey getEncryptionKey() {
        byte[] keyBytes = Decoders.BASE64.decode(encryptionKey);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    /**
     * Extracts only non-sensitive data for logging
     * Decrypts the token to extract metadata safely
     *
     * @param token encrypted token to extract metadata from
     * @return token metadata string
     */
    public String getTokenMetadata(String token) {
        try {
            Claims claims = extractClaims(token);
            return String.format("issuer=%s, env=%s, type=%s, exp=%s",
                    claims.getIssuer(),
                    claims.get("env"),
                    claims.get("typ"),
                    claims.getExpiration());
        } catch (Exception e) {
            return "invalid_token";
        }
    }
}