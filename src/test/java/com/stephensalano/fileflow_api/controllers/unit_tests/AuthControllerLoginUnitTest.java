package com.stephensalano.fileflow_api.controllers.unit_tests;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.stephensalano.fileflow_api.configs.security.JwtService;
import com.stephensalano.fileflow_api.controllers.AuthController;
import com.stephensalano.fileflow_api.dto.requests.AuthRequest;
import com.stephensalano.fileflow_api.dto.responses.AuthResponse;
import com.stephensalano.fileflow_api.services.auth.AuthService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.http.MediaType;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
/**
 * What are we testing?
 * - We want to simulate a POST to /api/v1/auth/login with a JSON body like:
 *
 *  `{
 *       "usernameOrEmail": "testuser",
 *       "password": "Password123@"
 *  }`
 *
 * In a happy path, we mock authService.login(...) to return an AuthResponse with known values
 * We then verify:
 * 1. HTTP status is 200 OK
 * 2. Response has content-type: application/json
 * 3. JSON body has exactly the fields we expect, with the values we stubbed
 */
@WebMvcTest(AuthController.class) // spins up only the web layer for AuthController
public class AuthControllerLoginUnitTest {

    /**
     * Auth controller, depends on AuthService for login logic
     * We mock it so we control what authService.login(...) returns
     */
    @MockitoBean
    private AuthService authService;

    @MockitoBean
    private JwtService jwtService;

    /**
     * To simulate HTTP requests
     */
    @Autowired
    private MockMvc mockMvc;

    /**
     * To convert out Java Login request POJO into JSON
     */
    @Autowired
    private ObjectMapper objectMapper;

    @Test
    @WithMockUser // This makes Spring treat the request as "authenticated"
    void login_WithvalidCredentials_ShouldReturnAuthResponse() throws Exception {
        // 1. Arrange: build a sample AuthRequest
        AuthRequest loginRequest = new AuthRequest(
                "testuser",
                "Password123@"
        );

        // 2. Create a fake AuthResponse, using the static factory that sets token_type = "Bearer "
        AuthResponse fakeResponse = AuthResponse.of(
                "fakeAccessToken.jwt.part",
                "fakeRefreshToken.jwt.part",
                3600,
                "testuser",
                "test@example.com",
                "USER"
        );

        // 3. Stub AuthService.login(...) to return fake response
        when(authService.login(any(AuthRequest.class))).thenReturn(fakeResponse);

        // 4. Act: perform POST /api/v1/auth/login with JSON body
        mockMvc.perform(
                post("/api/v1/auth/login")
                        .with(csrf()) // Add CSRF token to bypass Spring Security's CSRF protection
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(loginRequest))
        )
                // 5. Assert: HTTP 200 OK
                .andExpect(status().isOk())
                // 6. Content-type must still be application/json
                .andExpect(content().contentType(MediaType.APPLICATION_JSON))
                // 7. Verify each JSON property exactly as in AuthResponse:
                .andExpect(jsonPath("$.success").value(true))
                .andExpect(jsonPath("$.message").value("Login successful"))
                .andExpect(jsonPath("$.data.access_token").value("fakeAccessToken.jwt.part"))
                .andExpect(jsonPath("$.data.refresh_token").value("fakeRefreshToken.jwt.part"))
                .andExpect(jsonPath("$.data.token_type").value("Bearer "))
                .andExpect(jsonPath("$.data.expires_in").value(3600))
                .andExpect(jsonPath("$.data.username").value("testuser"))
                .andExpect(jsonPath("$.data.email").value("test@example.com"))
                .andExpect(jsonPath("$.data.role").value("USER"));
    }

}
