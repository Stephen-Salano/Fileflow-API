package com.stephensalano.fileflow_api.controllers;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;


/**
 * Integration test for the AuthController
 *
 * These tests start up the full Spring application context and test the controller through HTTP requests
 * , ensuring that routing, JSON serialization, and the full request/response cycle work correctly
 */
@SpringBootTest // This starts up the full Spring application for testing
@AutoConfigureMockMvc // This sets up MockMvc to make HTTP
@ActiveProfiles("test")
public class AuthControllerIntegrationTest {

    @Autowired
    private MockMvc mockMvc; // This lets us make fake HTTP requests to our app

    /**
     * Test the health check endpoint
     *
     * This is our simplest test - it just verifies that:
     * 1. The endpoint responds with HTTP 200 (OK)
     * 2. The response is valid JSON
     * 3 The JSON contains the expected fields and values
     */
    @Test
    void healthEndpoint_ShouldReturnHealthyStatus() throws Exception{
        // Make a GET request to /api/v1/auth/health
        mockMvc.perform(get("/api/v1/auth/health"))
                // verify the HTTP status is 200 OK
                .andExpect(status().isOk())
                // Verify the response is JSON
                .andExpect(content().contentType("application/json"))
                // verify specific JSON fields and values
                .andExpect(jsonPath("$.status").value("healthy"))
                .andExpect(jsonPath("$.service").value("auth-controller"));
    }
}
