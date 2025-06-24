package com.stephensalano.fileflow_api.configs.security;

import com.stephensalano.fileflow_api.dto.security.SecurityContext;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.env.Environment;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.util.*;
import java.util.function.Function;

@Service
@Slf4j
@RequiredArgsConstructor
public class JwtService {

    private final Environment environment;

//    @Value("${jwt.encryption-key}")
//    private String encryptionKey;

    @Value("${jwt.signing-key}")
    private String signingKey;

    @Getter
    @Value("${jwt.access-token-expiration}")
    private long accessTokenExpiration;

    @Getter
    @Value("${jwt.refresh-token-expiration}")
    private long refreshTokenExpiration;

    @Value("${spring.application.name}")
    private String applicationName;

    @Value("${spring.application.frontend-url}")
    private String audience;


//    private static final AeadAlgorithm ENCRYPTION_ALGORITHM = Jwts.ENC.A256GCM;
//    private static final SecretKeyAlgorithm KEY_MANAGEMENT_ALGORITHM = Jwts.KEY.A256KW;
    private static final String ENVIRONMENT_CLAIM = "env";
    private static final String TOKEN_TYPE_CLAIM = "typ";
    private static final String IP_CLAIM = "ip";
    private static final String FP_CLAIM = "fp"; // fingerprint claim

    /**
     * Generates an access token for the given user details with additional security context (IP, fingerprint)
     * @param userDetails the user details
     * @return the generated token
     */
    public String generateAccessToken(UserDetails userDetails) {

        log.debug("Generating access token for user: {}", userDetails.getUsername());
        return generateToken(userDetails, null, "access", accessTokenExpiration);

    }

    public String generateRefreshToken(UserDetails userDetails) {
        log.debug("Generating refresh token for user: {}", userDetails.getUsername());
        return generateToken(userDetails, null, "refresh", refreshTokenExpiration * 1000);
    }

    private String generateToken(UserDetails userDetails, SecurityContext context, String type, long expiration) {
        Date now = new Date();
        Date exp = new Date(now.getTime() + expiration);

        Map<String, Object> claims = new HashMap<>();
        claims.put(TOKEN_TYPE_CLAIM, type);
        claims.put(ENVIRONMENT_CLAIM, getCurrentEnvironment());
        claims.put("aud", Collections.singleton(audience));

        if (context != null){
            claims.put(IP_CLAIM, context.ipAddress());
            claims.put(FP_CLAIM, context.fingerprintHash());
        }

        String issuer = getIssuer();

        String token = Jwts.builder()
                .claims(claims)
                .subject(userDetails.getUsername())
                .issuer(issuer)
                .issuedAt(now)
                .expiration(exp)
                .signWith(getSigningKey())
                .compact();

        log.info("Generated token: user={}, type={}, expires={}c, aud={}",
                userDetails.getUsername(), type, exp, audience);
        return token;
    }

    public String getIssuer() {
        return applicationName + '_' + getCurrentEnvironment();
    }

    public boolean isTokenValid(String token, UserDetails userDetails) {
        try{
            String username = extractUsername(token);
            boolean valid = username.equals(userDetails.getUsername())
                    && !isTokenExpired(token)
                    && validateIssuer(token)
                    && validateAudience(token);
            log.debug("Token Validity for {}:{}", username, valid);
            return valid;
        } catch (Exception e){
            log.warn("Token validation failed: {}", e.getMessage());
            return false;
        }

    }

    public String extractUsername(String token){
        return extractClaim(token, Claims::getSubject);
    }

    public String extractIp(String token){
        return extractClaim(token, claims -> claims.get(IP_CLAIM, String.class));
    }
    public String extractFingerprintHash(String token){
        return extractClaim(token, claims -> claims.get(FP_CLAIM, String.class));
    }


    private boolean validateIssuer(String token) {
        try {
            String expected = applicationName + "_" + getCurrentEnvironment();
            String actual = extractClaim(token, Claims::getIssuer);
            boolean valid = expected.equals(actual);
            if (!valid) log.warn("Issuer mismatch: expected={}, actual={}", expected, actual);
            return valid;
        }catch (Exception e){
            log.warn("Issuer validation failed: {}", e.getMessage());
            return false;
        }
    }

    private boolean validateAudience(String token){
       try{
           Set<String> audienceSet = extractClaim(token, Claims::getAudience);
           boolean valid = audienceSet != null && audienceSet.contains(audience);
           if (!valid) log.warn("Audience mismatch: expected contains={}, actual={}", audience, audienceSet);
           return valid;
       } catch (Exception e){
           log.warn("Audience validation failed: {}", e.getMessage());
           return false;
       }
    }

    private boolean isTokenExpired(String token) {
        try{
            Date exp = extractClaim(token, Claims::getExpiration);
            boolean expired = exp.before(new Date());
            if (expired) log.debug("Token expired at {}", exp);
            return expired;
        } catch (Exception e){
            log.warn("Token expiration check failed: {}", e.getMessage());
            return true;
        }
    }

    private <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    public Claims extractAllClaims(String token) {

        try {
            return Jwts.parser()
                    .verifyWith(getSigningKey())
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();
        } catch (Exception e){
            log.error("Token parsing failed: {}", e.getMessage(), e);
            throw new RuntimeException("Failed to parse JWT token", e);
        }
    }

    public SecretKey getSigningKey(){
        try{
            byte[] keyBytes = Decoders.BASE64.decode(signingKey);
            return Keys.hmacShaKeyFor(keyBytes);
        } catch (Exception e){
            log.error("Signing key error: {}", e.getMessage(), e);
            throw new RuntimeException("Invalid Signing Key", e);
        }
    }

    private String getCurrentEnvironment() {

        return Arrays.stream(environment.getActiveProfiles())
                .filter(p -> List.of("dev", "test", "prod").contains(p))
                .findFirst()
                .orElse("default");
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