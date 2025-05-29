package com.stephensalano.fileflow_api.services.auth;

import com.stephensalano.fileflow_api.configs.security.JwtService;
import com.stephensalano.fileflow_api.dto.requests.AuthRequest;
import com.stephensalano.fileflow_api.dto.requests.RegisterRequest;
import com.stephensalano.fileflow_api.dto.responses.AuthResponse;
import com.stephensalano.fileflow_api.entities.*;
import com.stephensalano.fileflow_api.repository.AccountRepository;
import com.stephensalano.fileflow_api.repository.RefreshTokenRepository;
import com.stephensalano.fileflow_api.repository.UserRepository;
import com.stephensalano.fileflow_api.services.email.EmailService;
import com.stephensalano.fileflow_api.services.verification_token.VerificationTokenService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.time.LocalDateTime;
import java.util.Optional;

@Service
@RequiredArgsConstructor
@Slf4j
public class AuthServiceImpl  implements AuthService{

    // DI
    private final UserRepository userRepository;
    private final AccountRepository accountRepository;
    private final PasswordEncoder passwordEncoder;
    private final VerificationTokenService verificationTokenService;
    private final EmailService emailService;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;
    private final RefreshTokenRepository refreshTokenRepository;

    @Override
    @Transactional
    public Account registerUser(RegisterRequest request) {
        // Validate the username and email are not already taken
        validateRegistrationData(request);

        // Create and save the User entity
        User user = createUser(request);
        User savedUser = userRepository.save(user);

        // Create and save the Account entity
        Account account = createAccount(request, savedUser);
        Account savedAccount = accountRepository.save(account);

        // Generate Verification token
        VerificationToken verificationToken = verificationTokenService.createToken(
                savedAccount, TokenTypes.VERIFICATION);

        // Send verification email
        boolean emailSent = emailService.sendVerificationEmail(
                request.email(), request.username(), verificationToken.getToken()
        );

        if (!emailSent){
            log.warn("Failed to send verification email to {}", request.email());
        }
        return savedAccount;

    }

    /**
     * Verifies a user's email using a token
     * This method is transactional to ensure data inconsistency
     * @param token The verification token
     * @return boolean if the email exits
     */
    @Override
    @Transactional
    public boolean verifyEmail(String token) {

        // Validate the token
        Optional<VerificationToken> verificationTokenOpt = verificationTokenService.validateToken(token);

        if (verificationTokenOpt.isEmpty()){
            log.info("Invalid or expired verification token: {}", token);
            return false;
        }

        VerificationToken verificationToken = verificationTokenOpt.get();
        Account account = verificationToken.getAccount();

        // Enable the account
        account.setEnabled(true);
        accountRepository.save(account);

        // Delete the used token
        verificationTokenService.deleteToken(verificationToken);

        // Send welcome email
        emailService.sendWelcomeEmail(account.getEmail(), account.getUsername());

        log.info("Email verified successfully for user: {}", account.getUsername());
        return true;
    }

    /**
     * Validates that the registration data is valid
     * Specifically checks that the username and email are not already taken.
     *
     * @param request the registration request
     * @throws IllegalArgumentException if validation fails
     */
    private void validateRegistrationData(RegisterRequest request) {
        // check if username already exists
        if (accountRepository.existsByUsername(request.username())){
            throw new IllegalArgumentException("Username already taken");
        }

        // check if email already exists
        if (accountRepository.existsByEmail(request.email())){
            throw new IllegalArgumentException("Email already registered");
        }
    }

    /**
     * Creates a new user entity from the registration request
     *
     * @param request the registration request
     * @return the created user entity
     */
    private User createUser(RegisterRequest request) {
        return User.builder()
                .firstName(request.firstName())
                .secondName(request.secondName())
                .build();
    }


    /**
     * Creates a new account entity from the registration request and associated user
     *
     * @param request The registration request
     * @param savedUser The associated User entity
     * @return the created account entity (not yet persisted)
     */
    private Account createAccount(RegisterRequest request, User savedUser) {
        return Account.builder()
                .user(savedUser)
                .username(request.username())
                .email(request.email())
                .password(passwordEncoder.encode(request.password()))
                .role(Role.USER)
                .enabled(false) // by default the account is disabled until email verification
                .accountNonLocked(true)
                .build();
    }

    @Override
    @Transactional
    public AuthResponse login(AuthRequest authRequest) {
        log.info("Login attempt for user: {}", authRequest.usernameOrEmail());

        try{
            // Authenticate the user
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            authRequest.usernameOrEmail(),
                            authRequest.password()
                    )
            );

            // Get the authenticated account
            Account account = (Account) authentication.getPrincipal();

            // Check if account is enabled
            if (!account.isEnabled()){
                throw new IllegalStateException("Account not verified. Please check your email for the verification link");
            }

            // Generate tokens
            String accessToken = jwtService.generateAccessToken(account);
            String refreshToken = jwtService.generateRefreshToken(account);

            // Save the refresh token to the database

            saveRefreshToken(account, refreshToken);

            log.info("Login successful for user: {}", account.getUsername());

            return AuthResponse.of(
                    accessToken, refreshToken, jwtService.getAccessTokenExpiration() / 100, // Converted to seconds
                    account.getUsername(), account.getEmail(), account.getRole().name()
            );

        } catch (AuthenticationException e){
            log.warn("Login failed for user: {} - {}", authRequest.usernameOrEmail(), e.getMessage());
            throw new IllegalArgumentException("Invalid username /email or password");
        }
    }

    @Override
    @Transactional
    public void logout(Authentication authentication) {
        if (authentication != null && authentication.getPrincipal() instanceof Account account){
            log.info("Logout requested for user: {}", account.getUsername());

            // invalidate all refresh tokens for this account
            refreshTokenRepository.invalidateAllByAccount(account);

            log.info("Logout successful for user: {}", account.getUsername());
        }
    }

    @Override
    @Transactional
    public AuthResponse refreshToken(String refreshToken) {
        log.debug("Token refresh attempt");

        // find the refresh token in the database
        RefreshToken storedToken = refreshTokenRepository.findByToken(refreshToken)
                .orElseThrow(() -> new IllegalArgumentException("Invalid refresh token "));

        // Check if token is expired or invalidated
        if (storedToken.isExpired() || storedToken.isInvalidated()){
            log.warn("Expired or invalidated refresh token used");
            throw new IllegalArgumentException("Refresh token expired or invalid");
        }

        Account account = storedToken.getAccount();

        // Generate new tokens
        String newAccessToken = jwtService.generateAccessToken(account);
        String newRefreshToken = jwtService.generateRefreshToken(account);

        // Invalidate old refresh token and save new ones
        storedToken.setInvalidated(true);
        refreshTokenRepository.save(storedToken);
        saveRefreshToken(account, newRefreshToken);

        log.info("Token refreshed successfully for user: {}", account.getUsername());

        return AuthResponse.of(
                newAccessToken, newRefreshToken,
                jwtService.getAccessTokenExpiration() / 100,
                account.getUsername(), account.getEmail(),
                account.getRole().name()
        );


    }

    /**
     * Saves a refresh token to the db
     * Removes any existing refreshToken for the account first
     * @param account The account the token belongs to
     * @param refreshToken the refreshToken to be saved
     */
    private void saveRefreshToken(Account account, String refreshToken) {
        // Remove existing refresh Token
        refreshTokenRepository.findByAccount(account)
                .ifPresent(existingToken -> {
                    existingToken.setInvalidated(true);
                    refreshTokenRepository.save(existingToken);
                });

        // create a new refreshToken
        RefreshToken newRefreshToken = new RefreshToken();
        newRefreshToken.setAccount(account);
        newRefreshToken.setToken(refreshToken);
        newRefreshToken.setExpiryDate(Instant.now().plusMillis(jwtService.getRefreshTokenExpiration()));
        newRefreshToken.setInvalidated(false);
        newRefreshToken.setCreatedAt(LocalDateTime.now());

        refreshTokenRepository.save(newRefreshToken);
    }
}
