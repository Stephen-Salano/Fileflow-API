package com.stephensalano.fileflow_api.configs.security;

import com.stephensalano.fileflow_api.entities.Account;
import com.stephensalano.fileflow_api.services.security.DeviceFingerprintService;
import com.stephensalano.fileflow_api.utils.SecurityUtils;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Optional;

@Component
@RequiredArgsConstructor
@Slf4j
public class JwtAuthFilter extends OncePerRequestFilter {

    private final JwtService jwtService;
    private final UserDetailsService userDetailsService;
    private final DeviceFingerprintService fingerprintService;

    private static final String AUTHORIZATION_HEADER = "Authorization";
    private static final String BEARER_PREFIX = "Bearer ";
    private static final int BEARER_PREFIX_LENGTH = 7;

    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain
    ) throws ServletException, IOException {

        // 1. Skip filter for public endpoints or if no token is present
        if (shouldNotFilter(request)) {
            filterChain.doFilter(request, response);
            return;
        }

        // 2. Extract token and attempt authentication
        extractBearerToken(request).ifPresent(token -> {
            try {
                authenticateRequest(token, request, response);
            } catch (JwtException e) {
                log.warn("Invalid JWT token received: {}. Details: {}", jwtService.getTokenMetadata(token), e.getMessage());
                sendError(response, HttpServletResponse.SC_UNAUTHORIZED, "Invalid or expired token");
            } catch (Exception e) {
                log.error("An unexpected error occurred during JWT processing for user.", e);
                sendError(response, HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Authentication processing error");
            }
        });

        // 3. Continue the filter chain
        filterChain.doFilter(request, response);
    }

    /**
     * Main authentication logic after a token has been extracted.
     */
    private void authenticateRequest(String token, HttpServletRequest request, HttpServletResponse response) {
        // Proceed only if there's no existing authentication
        if (SecurityContextHolder.getContext().getAuthentication() != null) {
            log.debug("User is already authenticated. Skipping JWT processing.");
            return;
        }

        String username = jwtService.extractUsername(token);
        UserDetails userDetails = userDetailsService.loadUserByUsername(username);

        if (validateRequest(token, userDetails, request, response)) {
            setAuthenticationContext(userDetails, request);
            log.info("Authenticated {} via JWT for request to {}", username, request.getRequestURI());
        }
    }

    /**
     * Groups all validation checks for an incoming authenticated request.
     * Returns true if all checks pass, false otherwise.
     */
    private boolean validateRequest(String token, UserDetails userDetails, HttpServletRequest request, HttpServletResponse response) {
        // Standard token validation (expiry, audience)
        if (!jwtService.isTokenValid(token, userDetails)) {
            sendError(response, HttpServletResponse.SC_UNAUTHORIZED, "Invalid token");
            return false;
        }

        Claims claims = jwtService.extractAllClaims(token);

        // Security validation (IP, Fingerprint, Issuer)
        if (!validateIssuer(claims) || !validateIpAddress(claims, request) || !validateDeviceFingerprint(claims, userDetails)) {
            // Specific error messages are logged within the validation methods
            sendError(response, HttpServletResponse.SC_FORBIDDEN, "Security validation failed");
            return false;
        }

        return true;
    }

    private boolean validateIssuer(Claims claims) {
        if (!jwtService.getIssuer().equals(claims.getIssuer())) {
            log.warn("Issuer mismatch: expected={}, actual={}", jwtService.getIssuer(), claims.getIssuer());
            return false;
        }
        return true;
    }

    private boolean validateIpAddress(Claims claims, HttpServletRequest request) {
        String tokenIp = claims.get("ip", String.class);
        String requestIp = SecurityUtils.extractClientIp(request); // Use the utility class

        if (tokenIp == null || !tokenIp.equals(requestIp)) {
            log.warn("IP mismatch for user {}: tokenIp={}, requestIp={}", claims.getSubject(), tokenIp, requestIp);
            return false;
        }
        return true;
    }

    private boolean validateDeviceFingerprint(Claims claims, UserDetails userDetails) {
        String fpHash = claims.get("fp", String.class);
        Account account = (Account) userDetails;

        if (fpHash == null || !fingerprintService.isKnownDevice(account, fpHash)) {
            log.warn("Unknown device for user {}: fp={}", userDetails.getUsername(), fpHash);
            return false;
        }
        return true;
    }

    /**
     * Creates and sets the authentication token in the Spring Security context.
     */
    private void setAuthenticationContext(UserDetails userDetails, HttpServletRequest request) {
        var authToken = new UsernamePasswordAuthenticationToken(
                userDetails, null, userDetails.getAuthorities()
        );
        authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
        SecurityContextHolder.getContext().setAuthentication(authToken);
    }

    /**
     * Extracts the "Bearer" token from the Authorization header.
     */
    private Optional<String> extractBearerToken(HttpServletRequest request) {
        final String authHeader = request.getHeader(AUTHORIZATION_HEADER);
        if (authHeader != null && authHeader.startsWith(BEARER_PREFIX) && authHeader.length() > BEARER_PREFIX_LENGTH) {
            return Optional.of(authHeader.substring(BEARER_PREFIX_LENGTH));
        }
        return Optional.empty();
    }

    private void sendError(@NonNull HttpServletResponse response, int status, String message) {
        if (response.isCommitted()) {
            log.warn("Response already committed. Unable to send error {}: {}", status, message);
            return;
        }
        response.setStatus(status);
        response.setContentType("application/json");
        try {
            response.getWriter().write(
                    String.format("{\"success\":false,\"message\":\"%s\"}", message));
        } catch (IOException e) {
            log.error("Failed to write error response", e);
        }
    }

    protected boolean shouldNotFilter(HttpServletRequest req) {
        String path = req.getRequestURI();
        return path.startsWith("/api/v1/auth/register")
                || path.startsWith("/api/v1/auth/verify")
                || path.startsWith("/api/v1/auth/health")
                || path.startsWith("/api/v1/auth/login")
                || path.startsWith("/h2-console")
                || path.startsWith("/actuator");
    }
}