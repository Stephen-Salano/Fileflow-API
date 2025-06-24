package com.stephensalano.fileflow_api.configs;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.Arrays;

@Configuration
public class CorsConfig {

    @Value("${spring.application.frontend-url}")
    private String frontendUrl;

    @Bean
    public CorsConfigurationSource corsConfigurationSource(){
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();

        // Main API CORS configuration
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOriginPatterns(Arrays.asList(
                frontendUrl,
                "http://localhost:3000",
                "http://localhost:3001",
                "http://localhost:4200",
                "http://127.0.0.1:3000"
        ));

        configuration.setAllowedMethods(Arrays.asList(
                "GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"
        ));

        configuration.setAllowedHeaders(Arrays.asList(
                "Authorization",
                "Content-Type",
                "Accept",
                "Origin",
                "Access-Control-Request-Method",
                "Access-Control-Request-Headers",
                "X-Requested-With",
                "Cache-Control"
        ));

        configuration.setExposedHeaders(Arrays.asList(
                "Authorization",
                "Access-Control-Allow-Origin",
                "Access-Control-Allow-Credentials"
        ));

        configuration.setAllowCredentials(true);
        configuration.setMaxAge(3600L);

        // Apply to API endpoints only
        source.registerCorsConfiguration("/api/**", configuration);

        // H2 Console - Allow all origins without CORS restrictions
        CorsConfiguration h2Config = new CorsConfiguration();
        h2Config.addAllowedOriginPattern("*");
        h2Config.addAllowedHeader("*");
        h2Config.addAllowedMethod("*");
        h2Config.setAllowCredentials(false);
        source.registerCorsConfiguration("/h2-console/**", h2Config);

        return source;
    }
}