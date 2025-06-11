package com.stephensalano.fileflow_api.controllers;

import com.stephensalano.fileflow_api.dto.requests.AuthRequest;
import com.stephensalano.fileflow_api.dto.requests.RegisterRequest;
import com.stephensalano.fileflow_api.dto.responses.AuthResponse;
import com.stephensalano.fileflow_api.entities.Account;
import com.stephensalano.fileflow_api.services.auth.AuthService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.NestedExceptionUtils;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
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
            // Print the full stack trace of the *root cause*
            Throwable root = NestedExceptionUtils.getRootCause(e);
            if (root != null) {
                log.error("Registration failed: root cause = {}", root.getMessage(), root);
            } else {
                log.error("Registration failed: {}", e.getMessage(), e);
            }

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


    /**
     * Handles user login requests
     *
     * @param authRequest The login credentials
     * @return ResponseEntity with authentication tokens or error message
     */
    @PostMapping("/login")
    public ResponseEntity<Map<String, Object>> login(
            @Valid @RequestBody AuthRequest authRequest
            ){
        Authentication currentAuthentication = SecurityContextHolder.getContext().getAuthentication();

        //Check if a user is already authenticated and not an anonymous user
        // "anonymousUser" is the default principal for unauthenticated users in Springboot Security
        if(currentAuthentication != null && currentAuthentication.isAuthenticated() &&
                !"anonymousUser".equals(currentAuthentication.getPrincipal())){
            log.warn("Login attempt by already authenticated user: {}", currentAuthentication.getName());
            return ResponseEntity.status(HttpStatus.CONFLICT)
                    .body(Map.of(
                            "success", false,
                            "message", "You are already logged in."
                    ));
        }

        log.info("Login attempt for: {}", authRequest.usernameOrEmail());

        try{
            AuthResponse authResponse = authService.login(authRequest);

            return ResponseEntity.ok(Map.of(
                    "success", true,
                    "message", "Login successful",
                    "data", authResponse
            ));
        }catch (IllegalArgumentException e){
            log.warn("Login failed for {}: {}", authRequest.usernameOrEmail(), e.getMessage());

            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of(
                            "success", false,
                            "message", e.getMessage()
                    ));
        } catch (IllegalStateException e){
            log.warn("Account not verified for {}: {}", authRequest.usernameOrEmail(), e.getMessage());
            return ResponseEntity.status(HttpStatus.FORBIDDEN)
                    .body(Map.of(
                            "success", false,
                            "message", e.getMessage()
                    ));
        } catch (Exception e){
            log.error("Unexpected error during login for {}: {}",
                    authRequest.usernameOrEmail(), e.getMessage());

            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of(
                            "success", false,
                            "message", "Login failed due to server error. Please try again later."
                    ));
        }

    }

    /**
     * Handles user logout requests
     *
     * @param authentication The current user's authentication
     * @return ResponseEntity with logout confirmation
     */
    @PostMapping("/logout")
    public ResponseEntity<Map<String, Object>>logout(Authentication authentication){
        try{
            authService.logout(authentication);

            return ResponseEntity.ok(Map.of(
                    "success", true,
                    "message", "logout successful"
            ));
        } catch (Exception e){
            log.error("Error during logout: {}", e.getMessage());

            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of(
                            "success", false,
                            "message", "logout failed due to server error"
                    ));
        }
    }

    /**
     * Handles token refresh requests
     *
     * @param requestBody Map containing the refresh token
     * @return ResponseEntity with new tokens or error message
     */
    @PostMapping("/refresh")
    public ResponseEntity<Map<String, Object>> refreshToken(
            @RequestBody Map<String, String> requestBody
    ){
        String refreshToken = requestBody.get("refresh_token");

        if(refreshToken == null || refreshToken.trim().isEmpty()){
            return ResponseEntity.badRequest()
                    .body(Map.of(
                            "success", false,
                            "message", "refresh token is required"
                    ));
        }

        try{
            AuthResponse authResponse = authService.refreshToken(refreshToken);

            return ResponseEntity.ok(Map.of(
                    "success", true,
                    "message", "Token refreshed successfully",
                    "data", authResponse
            ));
        } catch (IllegalArgumentException e){
            log.warn("Token refresh failed: {}", e.getMessage());

            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of(
                            "success", false,
                            "message", e.getMessage()
                    ));

        } catch (Exception e) {
            log.error("Unexpected error during token refresh: {}", e.getMessage());

            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of(
                            "success", false,
                            "message", "Token refresh failed due to server error"
                    ));
        }
    }
}
