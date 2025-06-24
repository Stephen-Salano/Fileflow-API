package com.stephensalano.fileflow_api.configs.security;

import com.stephensalano.fileflow_api.configs.SecurityHeadersConfig;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final JwtAuthFilter jwtAuthFilter;
    private final UserDetailsService userDetailsService;
    private final SecurityHeadersConfig securityHeadersConfig;
    private final Environment environment;
    private final CorsConfigurationSource corsConfigurationSource;

    // Public endpoints
    private static final String[] PUBLIC_ENDPOINTS = {
            "/api/v1/auth/register",
            "/api/v1/auth/login",
            "/api/v1/auth/verify"
    };
    // Dev/ test endpoints
    private static final String[] DEV_TEST_ENDPOINTS = {
            "/api/v1/auth/health",
            "/swagger-ui/**",
            "/swagger-ui.html",
            "/v3/api-docs/**",
            "/h2-console/**",
            "/actuator/**"
    };

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider authenticationProvider = new DaoAuthenticationProvider();
        authenticationProvider.setUserDetailsService(userDetailsService);
        authenticationProvider.setPasswordEncoder(passwordEncoder());
        return authenticationProvider;
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception {
        return configuration.getAuthenticationManager();
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

        List<String> permitList = new ArrayList<>(List.of(PUBLIC_ENDPOINTS));
        boolean isDevOrTest = Arrays.stream(environment.getActiveProfiles())
                .anyMatch(p -> p.equalsIgnoreCase("dev") || p.equalsIgnoreCase("test"));

        if (isDevOrTest) {
            permitList.addAll(List.of(DEV_TEST_ENDPOINTS));
        }

        http
                .csrf(csrf -> {
                    if (isDevOrTest) {
                        // Disable CSRF for H2 console and other dev endpoints
                        csrf.ignoringRequestMatchers("/h2-console/**", "/actuator/**")
                                .disable();
                    } else {
                        csrf.disable();
                    }
                })
                .cors(cors -> {
                    if (isDevOrTest) {
                        // For dev/test: disable CORS for H2, use custom config for API
                        cors.configurationSource(request -> {
                            if (request.getRequestURI().startsWith("/h2-console")) {
                                return new CorsConfiguration().applyPermitDefaultValues();
                            }
                            return corsConfigurationSource.getCorsConfiguration(request);
                        });
                    } else {
                        cors.configurationSource(corsConfigurationSource);
                    }
                })
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers(permitList.toArray(new String[0])).permitAll()
                        .requestMatchers("/api/v1/admin/**").hasRole("ADMIN")
                        .anyRequest().authenticated()
                )
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authenticationProvider(authenticationProvider())
                .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class)
                .addFilterAfter(securityHeadersConfig, UsernamePasswordAuthenticationFilter.class);

        if (isDevOrTest) {
            http.headers(headers -> headers
                    .frameOptions(HeadersConfigurer.FrameOptionsConfig::sameOrigin)
                    .httpStrictTransportSecurity(HeadersConfigurer.HstsConfig::disable)
            );
        }

        return http.build();
    }
}