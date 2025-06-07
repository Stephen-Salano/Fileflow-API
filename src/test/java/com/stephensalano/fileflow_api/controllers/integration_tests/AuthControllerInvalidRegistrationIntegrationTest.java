package com.stephensalano.fileflow_api.controllers.integration_tests;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.stephensalano.fileflow_api.dto.requests.RegisterRequest;
import com.stephensalano.fileflow_api.services.email.EmailService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest // Full Spring context
@AutoConfigureMockMvc
@ActiveProfiles("test")
public class AuthControllerInvalidRegistrationIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    // Replace the real EmailServiceImpl with a Mockito mock
    @MockitoBean
    private EmailService emailService;

    @Test
    void register_WithInvalidEmail_ShouldReturnBadRequest() throws Exception {
        RegisterRequest invalidRequest = new RegisterRequest(
                "not-an-email",
                "validuser",
                "Password123@",
                "John",
                "Doe"
        );

        mockMvc.perform(post("/api/v1/auth/register")
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(invalidRequest)))
                .andExpect(status().isBadRequest())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON));
    }

    @Test
    void register_WithWeakPassword_ShouldReturnBadRequest() throws Exception {
        RegisterRequest invalidRequest = new RegisterRequest(
                "test@example.com",
                "validuser",
                "weak",
                "John",
                "Doe"
        );

        mockMvc.perform(post("/api/v1/auth/register")
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(invalidRequest)))
                .andExpect(status().isBadRequest())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON));
    }

    @Test
    void register_WithBlankFields_ShouldReturnBadRequest() throws Exception {

        RegisterRequest invalidRequest = new RegisterRequest(
                "",
                "",
                "Password123@",
                "",
                ""
        );

        mockMvc.perform(post("/api/v1/auth/register")
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(invalidRequest)))
                .andExpect(status().isBadRequest())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON));
    }

    @Test
    void register_WithDuplicateUsername_ShouldReturnBadRequest() throws Exception {

        when(emailService.sendVerificationEmail(anyString(), anyString(), anyString()))
                .thenReturn(true);
        // First, register a user so that “duplicateuser” is taken
        RegisterRequest firstUser = new RegisterRequest(
                "first@example.com",
                "duplicateuser",
                "Password123@",
                "John",
                "Doe"
        );

        mockMvc.perform(post("/api/v1/auth/register")
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(firstUser)))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.success").value(true));

        // Now attempt to register another with the same username but different email
        RegisterRequest duplicateUsernameRequest = new RegisterRequest(
                "different@example.com",
                "duplicateuser",
                "Password@123",
                "Jane",
                "Smith"
        );

        mockMvc.perform(post("/api/v1/auth/register")
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(duplicateUsernameRequest)))
                .andExpect(status().isBadRequest())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.success").value(false))
                .andExpect(jsonPath("$.message").value("Username already taken"));
    }

    @Test
    void register_WithDuplicateEmail_ShouldReturnBadRequest() throws Exception {

        when(emailService.sendVerificationEmail(anyString(), anyString(), anyString()))
                .thenReturn(true);

        // First, register a user so that “duplicate@example.com” is taken
        RegisterRequest firstUser = new RegisterRequest(
                "duplicate@example.com",
                "firstuser",
                "Password123@",
                "John",
                "Doe"
        );

        mockMvc.perform(post("/api/v1/auth/register")
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(firstUser)))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.success").value(true));


        // Now attempt to register another with the same email but different username
        RegisterRequest duplicateEmailRequest = new RegisterRequest(
                "duplicate@example.com",
                "seconduser",
                "Password123@",
                "Jane",
                "Smith"
        );

        mockMvc.perform(post("/api/v1/auth/register")
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(duplicateEmailRequest)))
                .andExpect(status().isBadRequest())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.success").value(false))
                .andExpect(jsonPath("$.message").value("Email already registered"));
    }
}
