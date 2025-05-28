package com.stephensalano.fileflow_api.configs;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.Arrays;

/**
 * CORS (Cross-Origin Resource Sharing) configuration
 *
 * This configuration allows the SpringBoot API to accept requests from different origins
 * which is essential since our frontend (React, Angular) runs on a different port from our backend
 *
 * CORS is a security feature implemented by web browsers that blocks requests from one domain to another unless
 * explicitly allowed by the server
 *
 * Key CORS concepts we handle here:
 * - Allowed Origins: which domains can make requests to our API
 * - Allowed Methods: which HTTP methods we permit
 * - Allowed Headers: which headers can be sent with requests
 * - Credentials: Whether cookies and authentication can be included
 */

@Configuration
public class CorsConfig {

    // Inject frontend URL from application.yaml
    @Value("${spring.application.frontend-url}")
    private String frontendUrl;

    /**
     * CORS config source bean
     *
     * This bean defines the CORS policy for the entire app
     * Spring Security will use this configuration to handle preflight requests and
     * validate cross-origin requests
     *
     * @return CorsConfigurationSource with our CORS policy
     */
    @Bean
    public CorsConfigurationSource corsConfigurationSource(){
        CorsConfiguration configuration = new CorsConfiguration();

        //  the allowed origins
        // TODO: In production we will specify exact origins for security
        configuration.setAllowedOriginPatterns(Arrays.asList(
                frontendUrl, // our front end app
                "http://localhost:3000", // React default dev server
                "http://localhost:3001", // Alternative React port
                "http://localhost:4200", // Angular default dev server
                "http://127.0.0.1:3000"  // Alternative localhost format
        ));

        //  allowed HTTP methods
        configuration.setAllowedMethods(Arrays.asList(
                "GET",     // Reading data
                "POST",    // Creating data
                "PUT",     // Updating data (full replacement)
                "PATCH",   // Updating data (partial update)
                "DELETE",  // Deleting data
                "OPTIONS"  // Preflight requests
        ));

        //  allowed headers
        configuration.setAllowedHeaders(Arrays.asList(
                "Authorization",    // JWT tokens
                "Content-Type",     // Request body format (JSON, etc.)
                "Accept",          // Response format preferences
                "Origin",          // Request origin
                "Access-Control-Request-Method",  // Preflight method info
                "Access-Control-Request-Headers", // Preflight headers info
                "X-Requested-With", // AJAX request identifier
                "Cache-Control"     // Caching directives
        ));

        // Headers that the client can read from responses
        configuration.setExposedHeaders(Arrays.asList(
                "Authorization",           // In case we return new tokens
                "Access-Control-Allow-Origin",
                "Access-Control-Allow-Credentials"
        ));

        // Allow credentials (cookies, authorization headers)
        // This is required for JWT authentication via Authorization header
        configuration.setAllowCredentials(true);

        // Set max age for preflight cache (how long browsers cace CORS info)
        configuration.setMaxAge(360L); // 1hour

        // Apply this configuration to all endpoints
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);

        return source;
    }
}
