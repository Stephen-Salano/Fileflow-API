package com.stephensalano.fileflow_api.services.auth;

import com.stephensalano.fileflow_api.dto.requests.RegisterRequest;
import com.stephensalano.fileflow_api.entities.*;
import com.stephensalano.fileflow_api.repository.AccountRepository;
import com.stephensalano.fileflow_api.repository.UserRepository;
import com.stephensalano.fileflow_api.services.email.EmailService;
import com.stephensalano.fileflow_api.services.token.VerificationTokenService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

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


}
