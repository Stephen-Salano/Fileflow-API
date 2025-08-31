package com.stephensalano.fileflow_api.services.auth;

import com.stephensalano.fileflow_api.configs.security.JwtService;
import com.stephensalano.fileflow_api.dto.requests.AuthRequest;
import com.stephensalano.fileflow_api.dto.requests.DeviceFingerprintRequest;
import com.stephensalano.fileflow_api.dto.requests.PasswordResetRequest;
import com.stephensalano.fileflow_api.dto.requests.RegisterRequest;
import com.stephensalano.fileflow_api.dto.responses.AuthResponse;
import com.stephensalano.fileflow_api.dto.security.SecurityContext;
import com.stephensalano.fileflow_api.entities.*;
import com.stephensalano.fileflow_api.events.OnPasswordResetRequestEvent;
import com.stephensalano.fileflow_api.events.OnPasswordResetSuccessEvent;
import com.stephensalano.fileflow_api.events.OnRegistrationCompleteEvent;
import com.stephensalano.fileflow_api.events.OnWelcomeEvent;
import com.stephensalano.fileflow_api.repository.AccountRepository;
import com.stephensalano.fileflow_api.repository.RefreshTokenRepository;
import com.stephensalano.fileflow_api.repository.UserRepository;
import com.stephensalano.fileflow_api.services.security.DeviceFingerprintService;
import com.stephensalano.fileflow_api.services.verification_token.VerificationTokenService;
import com.stephensalano.fileflow_api.utils.SecurityUtils;
import com.stephensalano.fileflow_api.utils.ValidationUtils;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cache.Cache;
import org.springframework.cache.CacheManager;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import ua_parser.Client;
import ua_parser.Parser;

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
    // for device fingerprinting
    private final DeviceFingerprintService deviceFingerprintService;
    private final HttpServletRequest request;

    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;
    private final RefreshTokenRepository refreshTokenRepository;
    private final ApplicationEventPublisher eventPublisher;
    private final Parser uaParser;
    private final CacheManager cacheManager;

    @Override
    @Transactional
    public Account registerUser(RegisterRequest request) {
        try {
            // Validate the username and email are not already
            log.debug("Validating registration data (username/email) for: {}", request.username());
            validateRegistrationData(request);
            log.debug("Validation passed: username/email are free.");

            // Create and save the User entity
            User user = createUser(request);
            log.debug("Attempting to save User entity: {}", user);
            User savedUser = userRepository.save(user);
            log.debug("Saved User: {}", savedUser);

            // Create and save the Account entity
            Account account = createAccount(request, savedUser);
            log.debug("Attempting to save Account entity: {}", account);
            Account savedAccount = accountRepository.save(account);
            log.debug("Saved Account: {}", savedAccount);


            // Generate Verification token
            log.debug("Creating VerificationToken for accountId={}", savedAccount.getId());
            VerificationToken verificationToken = verificationTokenService.createToken(
                    savedAccount, TokenTypes.VERIFICATION);
            log.debug("Created VerificationToken: token={} expiresAt={}",
                    verificationToken.getToken(),
                    verificationToken.getExpiryDate());

            eventPublisher.publishEvent(new OnRegistrationCompleteEvent(
                    this,
                    request.email(),
                    request.username(),
                    verificationToken.getToken()
            ));
            log.info("Registration completed for user: {}. Verification email will be sent after transaction commit.",
                    savedAccount.getUsername());
            return savedAccount;
        } catch (Exception e) {
            log.error("Registration failed INSIDE registerUser(): {}", e.getMessage(), e);
            throw e;
        }

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
        Optional<VerificationToken> verificationTokenOpt = verificationTokenService.validateToken(token, TokenTypes.VERIFICATION);
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
        eventPublisher.publishEvent(new OnWelcomeEvent(
                this,
                account.getEmail(),
                account.getUsername()
        ));

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

            // Get the authenticated account principal
            Account principalAccount = (Account) authentication.getPrincipal();

            // Re-fetch the account to ensure it's a managed entity in the current transaction.
            // This prevents issues with detached entities caused by other transactional listeners (e.g., AuthenticationSuccessListener).
            Account account = accountRepository.findByUsername(principalAccount.getUsername())
                    .orElseThrow(() -> new IllegalStateException("Authenticated user not found in database post-authentication"));

            // Check if account is enabled
            if (!account.isEnabled()) {
                throw new IllegalStateException("Account not verified. Please check your email for the verification link");
            }

            // Generate tokens
            String accessToken = jwtService.generateAccessToken(account);
            String refreshToken = jwtService.generateRefreshToken(account);

            // Save the refresh token to the database
            saveRefreshToken(account, refreshToken);

            /*
              TODO: Add optional security check (future):
              --------------------------------------------------------------------------------------------------------
              In the future, we want to add an alert to the user when a login occurs from an unknown device:

              if(!deviceFingerprintService.isKnownDevice(account, fingerprintHash)){
                   // 1. Send the alert email: "New device logged in to your account from IP"
                   // 2. Optionally log an event / store audit entry
              }

              This check is skipped for now since registerFingerPrint() already handles new vs existing devices well
              -------------------------------------------------------------------------------------------------------
             */

            handleDeviceFingerprintRegistration(authRequest, account);

            log.info("Login successful for user: {}", account.getUsername());

            return AuthResponse.of(
                    accessToken, refreshToken, jwtService.getAccessTokenExpiration() / 1000, // Converted to seconds
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

            // 2 We perform the device specific cleanup from the current session
//            handleDeviceFingerprintLogout(account);

            log.info("Logout successful for user: {}", account.getUsername());
        }
    }

    /**
     * Incase we want to remove that device once and for all
     * Extracts the device fingerprint from the current session's JWT and removes it.
     * This is a non-critical operation; failure will be logged but will not stop the logout process.
     *
     * @param account The account being logged out.
     */
    private void handleDeviceFingerprintLogout(Account account) {
        final String authHeader = request.getHeader("Authorization");
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return; // No token present, nothing to clean up.
        }

        final String token = authHeader.substring(7);
        try {
            String fpHash = jwtService.extractFingerprintHash(token);
            if (fpHash != null && !fpHash.isBlank()) {
                log.debug("Removing device fingerprint on logout: {}", fpHash);
                deviceFingerprintService.removeDevice(account, fpHash);
            }
        } catch (Exception e) {
            // This is not a critical failure. The user is logged out regardless.
            log.warn("Could not extract or remove fingerprint on logout for user {}: {}", account.getUsername(), e.getMessage());
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
                jwtService.getAccessTokenExpiration() / 1000, // Converted to seconds
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
        // Invalidate all previous refresh tokens for this user for enhanced security.
        refreshTokenRepository.invalidateAllByAccount(account);

        // create a new refreshToken
        RefreshToken newRefreshToken = new RefreshToken();
        newRefreshToken.setAccount(account);
        newRefreshToken.setToken(refreshToken);
        newRefreshToken.setExpiryDate(Instant.now().plusMillis(jwtService.getRefreshTokenExpiration()));
        newRefreshToken.setInvalidated(false);
        newRefreshToken.setCreatedAt(LocalDateTime.now());

        refreshTokenRepository.save(newRefreshToken);
    }

    /**
     * Handles the asynchronous registration of device fingerprints during login.
     *
     * @param authRequest The authentication request containing the fingerprint hash.
     * @param account The authenticated account.
     */
    private void handleDeviceFingerprintRegistration(AuthRequest authRequest, Account account) {
        String fingerprintHash = authRequest.fingerprintHash();
        if (fingerprintHash != null && !fingerprintHash.isBlank()) {
            String userAgent = request.getHeader("User-Agent");
            String ipAddress = SecurityUtils.extractClientIp(request);
            Client c = uaParser.parse(userAgent);
            String browser = c.userAgent.family;
            String os = c.os.family;
            String deviceType = c.device.family;


            SecurityContext securityContext = new SecurityContext(
                    fingerprintHash, userAgent, ipAddress, browser, os, deviceType
            );

            DeviceFingerprintRequest fingerprintRequest = new DeviceFingerprintRequest(
                    securityContext.fingerprintHash(),
                    securityContext.userAgent(),
                    securityContext.ipAddress(),
                    securityContext.browser(),
                    securityContext.os(),
                    securityContext.deviceType()
            );

            deviceFingerprintService.registerFingerprint(account, fingerprintRequest)
                    .exceptionally(ex -> { log.warn("Async device registration failed for user {}: {}", account.getUsername(), ex.getMessage()); return null; });
        }
    }

    @Override
    @Transactional
    public void requestPasswordReset(String email) {
        log.info("Password reset requested for email: {}", email);
        Account account = accountRepository.findByEmail(email)
                .orElse(null); // Find account, but throw an error to prevent email enumeration

        if (account != null){
            // Generate a password reset token
            VerificationToken resetToken = verificationTokenService.createToken(account, TokenTypes.PASSWORD_RESET);

            // publish an event to send the email
            eventPublisher.publishEvent(new OnPasswordResetRequestEvent(
                    this,
                    account.getEmail(),
                    account.getUsername(),
                    resetToken.getToken()

            ));
            log.info("Password reset token generated for user: {}. email will be sent", account.getUsername());

        } else {
            // Security: Do not reveal that the email doesn't exist
            log.warn("Password reset requested for non-existent email: {} No action taken", email);
        }
    }

    @Override
    @Transactional
    public void resetPassword(PasswordResetRequest request) {
        log.info("Attempting to reset password with a token");

        //Serverside validation check for matching passwords
        ValidationUtils.validatePasswordsMatch(request.newPassword(), request.confirmPassword());

        //Validate the token and ensure it's a PASSWORD_RESET token
        VerificationToken verificationToken = verificationTokenService.validateToken(request.token(), TokenTypes.PASSWORD_RESET)
                .orElseThrow(() -> new IllegalArgumentException("Invalid or expired reset token"));

        Account account = verificationToken.getAccount();

        // Evict user from cache before saving changes to ensure fresh data on next login
        evictUserFromCache(account.getUsername());
        evictUserFromCache(account.getEmail());

        // Set the new password
        account.setPassword(passwordEncoder.encode(request.newPassword()));
        account.setAccountNonLocked(true);
        account.setFailedLoginAttempts(0);
        accountRepository.save(account);

        // Invalidate all refresh tokens for this user security
        refreshTokenRepository.invalidateAllByAccount(account);
        log.info("All existing refresh token invalidated for user: {}", account.getUsername());

        // Delete the used password reset toke
        verificationTokenService.deleteToken(verificationToken);

        // Publish the event to notify the user of the successful change
        eventPublisher.publishEvent(new OnPasswordResetSuccessEvent(
                this,
                account.getEmail(),
                account.getUsername()
        ));
        log.info("Password reset successful for user: {}", account.getUsername());
    }

    private void evictUserFromCache(String key) {
        Cache usersCache = cacheManager.getCache("users");
        if (usersCache != null) {
            usersCache.evictIfPresent(key);
        }
    }
}
