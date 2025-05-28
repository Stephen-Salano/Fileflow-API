package com.stephensalano.fileflow_api.configs.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.constraints.NotNull;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * JWT Authentication Filter</p>
 *
 * This filter intercepts every HTTP request to check for JWT tokens in the Authorization header
 * It's responsible for:
 * - Extracting JWT tokens from requests
 * - Validating tokens using JwtService
 * - Setting up Spring Security authentication context for valid tokens
 * - Allowing requests to proceed with proper authentication state
 *
 * Extends `OncePerRequestFilter` to ensure it runs exactly once per request,
 * even if the request is forwarded or redirected.
 *
 */

@Component
@RequiredArgsConstructor
@Slf4j
public class JwtAuthFilter extends OncePerRequestFilter {

    // Dependency Injection
    private final JwtService jwtService;
    private final UserDetailsService userDetailsService;

    // constant for JWT token handling
    private static final String AUTHORIZATION_HEADER = "Authorization";
    private static final String BEARER_PREFIX = "Bearer ";
    private static final int BEARER_PREFIX_LENGTH = 7;

    /**
     * Main filter method that processes each HTTP request
     *
     * This method:
     * 1. Extracts JWT token from Authorization header
     * 2. Validates the token and extracts username
     * 3. Loads user details and sets authentication context
     * 4. Continues the filter chain
     *
     * @param request HTTP request
     * @param response HTTP response
     * @param filterChain chain to continue processing
     * @throws ServletException Throws Servlet exception error
     * @throws IOException throws IOException error
     */
    @Override
    protected void doFilterInternal(
            @NotNull HttpServletRequest request,
            @NotNull HttpServletResponse response,
            @NotNull FilterChain filterChain
    ) throws ServletException, IOException {

        // Extract Authorization header from request
        final String authHeader = request.getHeader(AUTHORIZATION_HEADER);

        // check if we have a valid Bearer token format
        if (!isValidBearerToken(authHeader)){
            log.debug("No valid Bearer token found in request to: {}", request.getRequestURI());
            // continue without authentication - let Spring security handle unauthorized access
            filterChain.doFilter(request, response);
            return;
        }
        // Extract the actual JWT token (remove "Bearer " prefix )
        final String jwt = authHeader.substring(BEARER_PREFIX_LENGTH);
        log.debug("JWT token extracted from request to: {}", request.getRequestURI());

        try{
            // extract username from the JWT token
            final String username = jwtService.extractUsername(jwt);

            // Only process if we have a username and no existing authentication
            if (username != null && SecurityContextHolder.getContext().getAuthentication() == null){
                log.debug("Processing JWT authentication for user: {}", username);

                // load user details from database
                UserDetails userDetails = userDetailsService.loadUserByUsername(username);

                // validate the token against user details
                if (jwtService.isTokenValid(jwt, userDetails)){
                    log.debug("JWT token is valid for user: {}", username);

                    // create authentication token for Spring Security
                    UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(
                            userDetails,
                            null, // No credentials needed - we validate via JWT
                            userDetails.getAuthorities()
                    );

                    // Set additional details from the web request
                    authenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

                    // Set the authentication in Spring Security context
                    SecurityContextHolder.getContext().setAuthentication(authenticationToken);

                    log.info("Successfully authenticated user: {} via JWT", username);
                } else {
                    log.warn("Invalid JWT token for user: {}", username);
                }
            }
        } catch (Exception e){
            // log JWT processing errors but don't stop the request
            log.error("Error processing JWT token: {}", e.getMessage());
            // Clear any partial authentication that might have been set
            SecurityContextHolder.clearContext();
        }

        // Continue with the filter chain regardless of authentication success/failure
        filterChain.doFilter(request, response);
    }

    /**
     * Checks if the Authorization header contains a valid Bearer token format
     *
     * @param authHeader The authorization header value
     * @return true if the header contains "Bearer " prefix, false otherwise
     */
    private boolean isValidBearerToken(String authHeader) {
        return authHeader != null &&
                authHeader.startsWith(BEARER_PREFIX) &&
                authHeader.length() > BEARER_PREFIX_LENGTH;
    }

    protected boolean shouldNotFilter(HttpServletRequest request){
        String path = request.getRequestURI();

        // Skip JWT processing for public endpoints
        return path.startsWith("/api/v1/auth/register") ||
                path.startsWith("/api/v1/auth/verify") ||
                path.startsWith("/api/v1/auth/health") ||
                path.startsWith("/h2-console") ||
                path.startsWith("/actuator");
    }

}
