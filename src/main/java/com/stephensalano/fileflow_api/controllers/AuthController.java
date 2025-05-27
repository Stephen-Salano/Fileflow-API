package com.stephensalano.fileflow_api.controllers;

import com.stephensalano.fileflow_api.dto.requests.RegisterRequest;
import com.stephensalano.fileflow_api.entities.Account;
import com.stephensalano.fileflow_api.services.auth.AuthService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

/**
 * REST Controller for authentication-related endpoints
 * 
 * This controller handles user registration and email verification
 * It acts as the HTTP interface layer, translating web requests into services calls and formatting
 * responses appropriately
 * 
 * Key responsibilities:
 * - Accept and validate HTTP requests
 * - Delegate business logic to services
 * - handle exceptions and return appropriate HTTP status codes
 * - Format responses in a consistent structure
 */

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
@Slf4j
public class AuthController {
    
    // DI for the auth service
    private final AuthService authService;

    /**
     * Handles user registration requests:
     * This endpoint accepts a POST request with user registration data, validates it using Bean validation annotations
     * and delegates the actual registration logi to AuthService
     *
     *
     * @param registerRequest The registration data from the client
     * @return ResponseEntity with registration status and message
     */
    @PostMapping("/register")
    public ResponseEntity<Map<String, Object>> register(
            @Valid @RequestBody RegisterRequest registerRequest
            ){
        // log the incoming registration attempt (without sensitive data)
        log.info("Registration attempt for username: {}", registerRequest.username());
        
        try{
            // Delegate the registration logic to our service layer
            Account registeredAccount = authService.registerUser(registerRequest);
            
            // log successful registration
            log.info("User registered successfully: {}", registeredAccount.getUsername());
            
            // Return success response with helpful information
            return ResponseEntity.status(HttpStatus.CREATED)
                    .body(Map.of(
                            "success", true,
                            "message", "Registration successful. Please check your email to verify your account.",
                            "username", registeredAccount.getUsername(),
                            "email", registeredAccount.getEmail()
                    ));
        } catch (IllegalArgumentException e){
            // Handle validation errors (like duplicate username/email)
            log.warn("Registration failed for {}: {}", registerRequest.username(), e.getMessage());

            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(Map.of(
                            "success", false,
                            "message", e.getMessage()
                    ));
        }catch (Exception e){
            // Handle unexpected errors
            log.error("Unexpected error during registration for {} : {}",
                    registerRequest.username(), e.getMessage());

            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of(
                            "success", false,
                            "message", "Registration failed due to a server error. Please try again later"
                    ));
        }
    }

    /**
     * Handles email verification requests
     *
     * This endpoint accepts a GET request with a verification token,
     * validates the token, and activates the user account if valid.
     *
     * The endpoint is designed to be called from email links, so it provides user-friendly responses that can be displayed
     * directly in a browser
     *
     * @param token the verification token from the email
     * @return ResponseEntity with verification status and message
     */
    @GetMapping("/verify")
    public ResponseEntity<Map<String, Object>>verifyEmail(@RequestParam("token") String token){
        // Log the verification attempt (token is logged for debugging)
        log.info("Email verification attempt with token: {}", token);

        try{
            // Delegate verification logic to our service layer
            boolean verificationSuccess = authService.verifyEmail(token);

            if (verificationSuccess) {
                // Return success response
                return ResponseEntity.ok(Map.of(
                        "success", true,
                        "message", "Email verified successfully! Your account is now active and you can log in.",
                        "redirectUrl", "/login" // Frontend will use this to redirect the user
                ));
            } else {
                log.warn("Email verification failed for token: {}", token);

                // Return failure response for invalid/expired token
                return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                        .body(Map.of(
                                "success", false,
                                "message", "Invalid or expired verification token. Please request  new verification email"
                        ));
            }
        } catch (Exception e){
            // Handle unexpected errors during verification
            log.error("Unexpected error during email verification for token {}: {}", token, e.getMessage(), e);

            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of(
                            "success", false,
                            "message", "Verification failed due to server error Please try again later."
                    ));
        }
    }

    /**
     * Health check endpoint for authentication service
     *
     * This simple endpoint can be used to verify that the authentication controller is working and accessible.
     * useful for monitoring and debugging purposes.
     *
     * @return simple success message
     */
    @GetMapping("/health")
    public ResponseEntity<Map<String, String>>health(){
        return ResponseEntity.ok(Map.of(
                "status", "healthy",
                "service", "auth-controller"
        ));
    }
}
