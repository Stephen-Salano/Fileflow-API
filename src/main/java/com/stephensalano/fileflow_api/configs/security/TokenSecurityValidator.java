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

import java.security.Key;
import java.util.Arrays;

@Component
@RequiredArgsConstructor
@Slf4j
public class TokenSecurityValidator {

    private final Environment environment;

    @Value("${jwt.secret-key}")
    private String secretKey;

    @Value("${spring.application.name}")
    private String applicationName;

    public boolean validateTokenSecurity(String token){
        try{
            Claims claims = extractClaims(token);

            return validateIssuer(claims) && validateEnvironment(claims) && validateTokenStructure(claims);

        } catch (Exception e){
            log.warn("Token security validation failed: {}", e.getMessage());
            return false;
        }
    }

    private Claims extractClaims(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(getSignInKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    private boolean validateIssuer(Claims claims) {
        String issuer = claims.getIssuer();
        String expectedIssuer = applicationName + "_" + getCurrentEnvironment();

        boolean valid = expectedIssuer.equals(issuer);
        if (!valid){
            log.warn("Invalid issuer: expected={}, actual={}", expectedIssuer, issuer);
        }
        return valid;
    }

    private boolean validateEnvironment(Claims claims) {
        String tokenEnv = (String) claims.get("env");
        String currentEnv = getCurrentEnvironment();

        boolean valid = currentEnv.equals(tokenEnv);
        if(!valid){
            log.warn("Environment mismatch: current={}, token={}", currentEnv, tokenEnv);
        }
        return valid;
    }

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

    private Key getSignInKey(){
        byte[] keyBytes = Decoders.BASE64.decode(secretKey);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    /**
     * Extracts only non-sensitive data for logging
     * @param token to be extracted
     * @return token metadata
     */
    public String getTokenMetadata(String token){
        try{
            Claims claims = extractClaims(token);
            return String.format("issuer=%s, env=%s, type=%s, exp=%s",
                    claims.getIssuer(),
                    claims.get("env"),
                    claims.get("typ"),
                    claims.getExpiration());
        } catch (Exception e){
            return "invalid_token";
        }
    }

}
