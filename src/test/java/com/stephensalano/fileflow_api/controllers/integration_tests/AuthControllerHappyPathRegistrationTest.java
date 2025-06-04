package com.stephensalano.fileflow_api.controllers.integration_tests;


import com.fasterxml.jackson.databind.ObjectMapper;
import com.stephensalano.fileflow_api.configs.security.JwtService;
import com.stephensalano.fileflow_api.dto.requests.RegisterRequest;
import com.stephensalano.fileflow_api.entities.*;
import com.stephensalano.fileflow_api.repository.AccountRepository;
import com.stephensalano.fileflow_api.repository.RefreshTokenRepository;
import com.stephensalano.fileflow_api.repository.UserRepository;
import com.stephensalano.fileflow_api.services.email.EmailService;
import com.stephensalano.fileflow_api.services.verification_token.VerificationTokenService;
import net.bytebuddy.asm.Advice;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.actuate.observability.AutoConfigureObservability;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import java.time.LocalDateTime;
import java.util.UUID;

import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * Integration test for AuthController - happy path register endpoint
 *
 * This test:
 * 1. Mocks out EmailService so no real SMTP is called
 * 2. Sends a valid RegisterRequest JSON payload
 * 3. Asserts HTTP 201, JSON content, and correct JSON fields
 * 4. Verifies that EmailService,sendVerificationEmail() was invoked twice.
 */

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
public class AuthControllerHappyPathRegistrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    // Replace the real EmailService bean with a Mockito mock
    @MockitoBean
    private EmailService emailService;

    @MockitoBean
    private VerificationTokenService verificationTokenService;

    // Add these mock beans
    @MockitoBean
    private UserRepository userRepository;

    @MockitoBean
    private JwtService jwtService;

    @MockitoBean
    private AuthenticationManager authenticationManager;

    @MockitoBean
    private RefreshTokenRepository refreshTokenRepository;

    @MockitoBean
    private PasswordEncoder passwordEncoder;

    // If we want to verify that data was saved, we could autowire AccountRepository
    @MockitoBean
    private AccountRepository accountRepository;



    /**
     * Clears any previous invocations or stubbings on the emailservice mock so each test starts with a fresh mock
     */
    @BeforeEach
    void setup(){
        // Reset all mocks
        Mockito.reset(emailService, verificationTokenService, userRepository, accountRepository, passwordEncoder);

        when(accountRepository.existsByUsername(anyString())).thenReturn(false);
        when(accountRepository.existsByEmail(anyString())).thenReturn(false);

        // Mock the password encoder
        when(passwordEncoder.encode(anyString())).thenReturn("encoded-password");

        // Mock user repository save - return user ith ID set
        when(userRepository.save(any(User.class))).thenAnswer(invocationOnMock -> {
            User user = invocationOnMock.getArgument(0);
            // Simulate database setting the ID
            User savedUser = User.builder()
                    .id(UUID.randomUUID())
                    .firstName(user.getFirstName())
                    .secondName(user.getSecondName())
                    .build();
            return savedUser;
        });

        // Mock account repository save - return account with ID and proper relationships
        when(accountRepository.save(any(Account.class))).thenAnswer(invocationOnMock -> {
            Account account = invocationOnMock.getArgument(0);
            // Create a saved account with ID
            return Account.builder()
                    .id(UUID.randomUUID())
                    .user(account.getUser())
                    .username(account.getUsername())
                    .email(account.getEmail())
                    .password(account.getPassword())
                    .role(Role.USER)
                    .enabled(false)
                    .accountNonLocked(true)
                    .anonymized(false)
                    .build();
        });


        // Mock verification token service
        when(verificationTokenService.createToken(any(Account.class), eq(TokenTypes.VERIFICATION)))
                .thenAnswer(invocationOnMock -> {
                    Account account = invocationOnMock.getArgument(0);
                    return VerificationToken.builder()
                            .id(UUID.randomUUID())
                            .account(account)
                            .token("dummy-verification-token-" + UUID.randomUUID())
                            .tokenTypes(TokenTypes.VERIFICATION)
                            .expiryDate(LocalDateTime.now().plusMinutes(15))
                            .build();
                });

        // mock email service
        when(emailService.sendVerificationEmail(anyString(), anyString(), anyString()))
                .thenReturn(true);
    }

    @Test
    void register_WithValidRequest_shouldReturnCreated() throws Exception{
        // 2) Build a valid registration request
        RegisterRequest request = new RegisterRequest(
                "alice@example.com",
                "alice123",
                "Password123@",
                "Alice",
                "Smith"
        );

        MvcResult result = mockMvc.perform(post("/api/v1/auth/register")
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andReturn();

        if (result.getResponse().getStatus() != 201) {
            System.out.println("Status: " + result.getResponse().getStatus());
            System.out.println("Response Body: " + result.getResponse().getContentAsString());
            if (result.getResolvedException() != null){
                System.out.println("Exception: " + result.getResolvedException().getMessage());
                result.getResolvedException().printStackTrace();
            }
        }

        // 3) Perform POST /api/v1/auth/register with the JSON payload (including CSRF)
        mockMvc.perform(post("/api/v1/auth/register")
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                // 4) Expect HTTP 201 CREATED
                .andExpect(status().isCreated())
                // 4b) Expect content type to be JSON
                .andExpect(content().contentType(MediaType.APPLICATION_JSON))
                // 4c) Expect JSON {"success": true}
                .andExpect(jsonPath("$.success").value(true))
                // 4d) Expect JSON "username": "alice123"
                .andExpect(jsonPath("$.username").value("alice123"))
                // 4e) Expect JSON "email": "alice@example.com"
                .andExpect(jsonPath("$.email").value("alice@example.com"));

        // 5) Verify that emailService.sendVerificationEmail() was called exactly once
        verify(accountRepository, times(2)).existsByUsername("alice123");
        verify(accountRepository, times(2)).existsByEmail("alice@example.com");
        verify(userRepository, times(2)).save(any(User.class));
        verify(accountRepository, times(2)).save(any(Account.class));
        verify(passwordEncoder, times(2)).encode("Password123@");
        verify(verificationTokenService, times(2)).createToken(any(Account.class),
                eq(TokenTypes.VERIFICATION));
        verify(emailService, times(2)).sendVerificationEmail(
                eq("alice@example.com"),
                eq("alice123"),
                anyString()
        );
    }


}
