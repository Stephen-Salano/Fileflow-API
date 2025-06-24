package com.stephensalano.fileflow_api.configs;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
@RequiredArgsConstructor
public class SecurityHeadersConfig extends OncePerRequestFilter {
    private final Environment environment;

    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain
    ) throws ServletException, IOException {

        // Security headers (apply to all environments)
        response.setHeader("X-Content-Type-Options", "nosniff");
        response.setHeader("X-Frame-Options", "DENY");
        response.setHeader("Referrer-Policy", "no-referrer");
        response.setHeader("Permissions-Policy", "geolocation=(), microphone=(), camera=()");

        // HSTS for production
        if (isProduction()){
            response.setHeader("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
        }

        // Minimal CSP
        response.setHeader("Content-Security-Policy", "default-src 'self'; script-src 'self'; object-src 'none';");

        filterChain.doFilter(request, response);
    }

    private boolean isProduction() {
        for (String profile: environment.getActiveProfiles()){
            if (profile.equalsIgnoreCase("prod")) return true;
        }
        return false;
    }
}
