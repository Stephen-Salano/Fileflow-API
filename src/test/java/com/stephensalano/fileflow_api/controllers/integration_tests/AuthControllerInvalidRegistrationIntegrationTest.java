package com.stephensalano.fileflow_api.controllers.integration_tests;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.stephensalano.fileflow_api.dto.requests.RegisterRequest;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;

/**
 * Integration test for AuthController - Testing invalid registration scenarios
 *
 * This test verifies that our validation works properly when users send invalid data to the
 * registration endpoint
 */

@SpringBootTest // Full Spring context
@AutoConfigureMockMvc // Sets up MockMvc
@ActiveProfiles("test") // Use test profile
public class AuthControllerInvalidRegistrationIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    /**
     * Test registration with invalid email format
     * This test sends a registration request with a malformed email and expects a 400 Bad Request response
     *
     * @throws Exception in case of failure
     */
    @Test
    void register_WithInvalidEmail_ShouldReturnBadRequest() throws Exception{
        // Arrange: create a request with invalid email
        RegisterRequest invalidRequest = new RegisterRequest(
                "not-an-email",
                "validuser",
                "Password123@",
                "John",
                "Doe"
        );

        // Act & ASSERT: Send request and verify response
        mockMvc.perform(post("/api/v1/auth/register")
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(invalidRequest)))
                // Should return 400 Bad request due to validation failure
                .andExpect(status().isBadRequest())
                //Should return JSON response
                .andExpect(content().contentType(MediaType.APPLICATION_JSON));
    }

    /**
     * Test registration with peak password
     *
     * This test sends a registration request with a password that doesn't meet our security requirements
     * @throws Exception in case of errors
     */
    @Test
    void register_WithWeakPassword_ShouldReturnBadRequest() throws Exception{
        // Arrange: Create a request with weak password
        RegisterRequest invalidRequest = new RegisterRequest(
                "test@example.com",
                "validuser",
                "weak",
                "John",
                "Doe"
        );

        // ACT & ASSERT: Send request and verify response
        mockMvc.perform(post("/api/v1/auth/register")
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(invalidRequest)))

                .andExpect(status().isBadRequest())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON));
    }

    /**
     * Test registration with blank fields
     *
     * This test sends a registration request with empty required fields
     * @throws Exception in case of error
     */
    @Test
    void register_WithBlankFields_ShouldReturnBadRequest()throws Exception{
        // Arrange: create a request with blank fields
        RegisterRequest invalidRequest = new RegisterRequest(
                "",
                "",
                "Password123@",
                "",
                ""
        );

        // ACT & ASSERT: send request and verify response
        mockMvc.perform(post("/api/v1/auth/register")
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(invalidRequest)))

                .andExpect(status().isBadRequest())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON));

    }

}
