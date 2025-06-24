package com.stephensalano.fileflow_api.configs.security;

import com.stephensalano.fileflow_api.configs.SecurityHeadersConfig;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;

import java.util.List;

/**
 * <h1>Spring Security Configuration</h1>
 *
 * <p>This configuration class sets up the security infrastructure for the application:</p>
 * <li> JWT-based stateless authentication</li>
 * <li> Password encoding with BCrypt</li>
 * <li> Authentication provider configuration</li>
 * <li> Security filter chain with proper endpoint protection</li>
 * <li> Integration of custom JWT authentication filter</li>
 *
 * <p>The configuration follows Spring Security 6.x patterns with lambda-based configuration and method-level
 * security annotations</p>
 */

@Configuration
@EnableWebSecurity
@EnableMethodSecurity // Enables @PreAuthorize, @PostAuthorize, etc
@RequiredArgsConstructor
public class SecurityConfig {

    // Dependencies injected via constructor
    private final JwtAuthFilter jwtAuthFilter;
    private final UserDetailsService userDetailsService;
    private final SecurityHeadersConfig securityHeadersConfig;

    /**
     * Password encoder bean using BCrypt
     * <p>
     * Bcrypt is a strong, adaptive hashing function designed for passwords.
     * It automatically handles salt generation and is resistant to rainbow table attacks
     *</p>
     * @return BCryptPasswordEncoder instance
     */
    @Bean
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }

    /**
     * Authentication provider that uses our custom UserDetailsService
     * <p>
     * This provider:
     * - Uses our AccountDetailsService to load user information
     * - Uses Bcrypt to verify passwords
     * - Integrates with Spring Security's authentication mechanism
     * </p>
     * @return DaoAuthenticationProvider configured for our current application
     */
    @Bean
    public AuthenticationProvider authenticationProvider(){
        DaoAuthenticationProvider authenticationProvider = new DaoAuthenticationProvider();
        authenticationProvider.setUserDetailsService(userDetailsService);
        authenticationProvider.setPasswordEncoder(passwordEncoder());
        return authenticationProvider;
    }

    /**
     * Authentication manager bean
     *<p>
     * This manager orchestrates the authentication process and is used by our login endpoint to authenticate user
     * credentials
     * </p>
     * @param configuration Spring's authentication configuration
     * @return AuthenticationManager instance
     * @throws Exception in case of errors
     */
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception{
        return configuration.getAuthenticationManager();
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http)throws Exception{
        http
                // Disable CSRF protection since we're using JWT stateless tokens
                .csrf(AbstractHttpConfigurer::disable)
                // Configure CORS - will use our C
                .cors(cors -> cors.configurationSource(request -> {
                    var corsConfig = new CorsConfiguration();
                    corsConfig.setAllowedOriginPatterns(List.of("*"));
                    corsConfig.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "OPTIONS"));
                    corsConfig.setAllowedHeaders(List.of("*"));
                    corsConfig.setAllowCredentials(true);
                    return corsConfig;
                        }))
                .authorizeHttpRequests(auth -> auth
                        // Public endpoints - no authentication required
                        .requestMatchers(
                                "/api/v1/auth/register",
                                "/api/v1/auth/login",
                                "/api/v1/auth/verify",
                                "/api/v1/auth/health"
                        ).permitAll()
                        // Development/ testing endpoints
                        .requestMatchers("/h2-console/**").permitAll()
                        .requestMatchers("/actuator/**").permitAll()

                        // Admin only endpoints
                        .requestMatchers("/api/v1/admin/**").hasRole("ADMIN")

                        // All other endpoints will require authentication
                        .anyRequest().authenticated()
                )
                // No HTTP session-every request must carry its JWT
                .sessionManagement(session -> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                )

                // Set up the auth provider
                .authenticationProvider(authenticationProvider())

                // Add our JWT filter before the standard username/password filter
                .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class)
                .addFilterAfter(securityHeadersConfig, UsernamePasswordAuthenticationFilter.class)

                // configure headers for H2 console (development only)
                /*
                  H2’s web console runs inside an HTML <iframe> by default.

                  Modern browsers, by default, will block any page from being framed if the server doesn’t
                  explicitly allow it (to protect against clickjacking).

                  Spring Security, by default, sets X-Frame-Options: DENY (no framing at all).

                  “It’s fine to embed this page in a frame—as long as the framing page comes from this
                  same application (same scheme/host/port).”
                 */
                .headers(headers -> headers
                        .contentSecurityPolicy(csp -> csp.policyDirectives(
                                "frame-ancestors 'self'"
                        ))
                );
        return http.build();
    }


}
