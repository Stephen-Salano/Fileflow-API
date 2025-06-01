package com.stephensalano.fileflow_api.controllers;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.stephensalano.fileflow_api.dto.requests.RegisterRequest;
import com.stephensalano.fileflow_api.entities.Account;
import com.stephensalano.fileflow_api.entities.Role;
import com.stephensalano.fileflow_api.entities.User;
import com.stephensalano.fileflow_api.configs.security.JwtService;
import com.stephensalano.fileflow_api.services.auth.AuthService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import java.util.UUID;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * Unit test for AuthController
 *
 * This tests ONLY the controller layer by mocking its dependencies.
 * It's fast because it doesn't start the full Spring application.
 */
@WebMvcTest(AuthController.class) // Only loads the web layer for AuthController
public class AuthControllerUnitTest {

    @Autowired
    private MockMvc mockMvc; // Simulates HTTP requests to our controller

    @MockitoBean // Creates a mock version of AuthService that we can control
    private AuthService authService;

    @MockitoBean // Mock the JwtService that AuthController depends on
    private JwtService jwtService;

    @Autowired
    private ObjectMapper objectMapper; // Converts Java objects to JSON

    @Test
    @WithMockUser // This bypasses Spring Security for this test
    void registerUser_WithValidData_ShouldReturnCreatedStatus() throws Exception {
        // ARRANGE: Set up test data and mock behavior

        // Create a sample registration request
        RegisterRequest registerRequest = new RegisterRequest(
                "test@example.com",
                "testuser",
                "Password123@",
                "John",
                "Doe" // This maps to 'secondName' field in your RegisterRequest
        );

        // Create a fake Account that our mock service will return
        User mockUser = User.builder()
                .firstName("John")
                .secondName("Doe")
                .build();

        Account mockAccount = Account.builder()
                .id(UUID.randomUUID())
                .username("testuser")
                .email("test@example.com")
                .role(Role.USER)
                .user(mockUser)
                .build();

        // Tell our mock AuthService what to return when registerUser is called
        when(authService.registerUser(any(RegisterRequest.class)))
                .thenReturn(mockAccount);

        // ACT & ASSERT: Make the request and verify the response
        mockMvc.perform(post("/api/v1/auth/register")
                        .with(csrf()) // Add CSRF token to bypass Spring Security's CSRF protection
                        .contentType(MediaType.APPLICATION_JSON) // Tell Spring we're sending JSON
                        .content(objectMapper.writeValueAsString(registerRequest))) // Convert request to JSON

                // Verify the response
                .andExpect(status().isCreated()) // HTTP 201
                .andExpect(content().contentType(MediaType.APPLICATION_JSON)) // Response is JSON
                .andExpect(jsonPath("$.success").value(true)) // success field is true
                .andExpect(jsonPath("$.message").value("Registration successful. Please check your email to verify your account."))
                .andExpect(jsonPath("$.username").value("testuser"))
                .andExpect(jsonPath("$.email").value("test@example.com"));
    }
}