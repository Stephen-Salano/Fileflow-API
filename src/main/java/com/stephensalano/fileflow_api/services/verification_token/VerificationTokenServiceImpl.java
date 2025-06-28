package com.stephensalano.fileflow_api.services.verification_token;

import com.stephensalano.fileflow_api.entities.Account;
import com.stephensalano.fileflow_api.entities.TokenTypes;
import com.stephensalano.fileflow_api.entities.VerificationToken;
import com.stephensalano.fileflow_api.repository.VerificationTokenRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.util.Base64;
import java.util.Optional;

@Service
@RequiredArgsConstructor
public class VerificationTokenServiceImpl implements VerificationTokenService{

    // Inject the Repository
    private final VerificationTokenRepository verificationTokenRepository;

    @Value("${app.verification-token.expiration-minutes:15}")
    private int expirationMinutes;

    @Value("${app.verification-token.token-length:32}")
    private int tokenLength;

    // SecureRandom is used to generate cryptographically strong random numbers
    private final SecureRandom secureRandom = new SecureRandom();

    @Override
    @Transactional
    public VerificationToken createToken(Account account, TokenTypes tokenTypes) {
        // First invalidate any existing tokens of the same type for this account
        invalidateTokens(account, tokenTypes);

        // create a new token with a secure random value and expiration time
        VerificationToken verificationToken = VerificationToken.builder()
                .account(account)
                .token(generateSecureToken())
                .tokenTypes(tokenTypes)
                .expiryDate(LocalDateTime.now().plusMinutes(expirationMinutes))
                .build();
        return verificationTokenRepository.save(verificationToken);
    }


    @Override
    @Transactional(readOnly = true)
    public Optional<VerificationToken> validateToken(String token, TokenTypes expectedType) {
        return verificationTokenRepository.findByToken(token)
                // Condition 1: The token must not be exipred
                .filter(verificationToken -> verificationToken.getExpiryDate().isAfter(LocalDateTime.now()))
                // Condition 2: The token must match the expected type
                .filter(verificationToken -> verificationToken.getTokenTypes() == expectedType);
    }


    @Override
    @Transactional
    public void invalidateTokens(Account account, TokenTypes tokenTypes) {
        // Find any existing token for this account and type
        Optional<VerificationToken> existingToken = verificationTokenRepository
                .findByAccountAndTokenTypes(account, tokenTypes);

        // Delete if found
        existingToken.ifPresent(verificationTokenRepository::delete); // `::` is a pointer to the repository's delete method

    }

    @Override
    public Optional<VerificationToken> findByToken(String token) {
        return verificationTokenRepository.findByToken(token);
    }

    @Override
    public void deleteToken(VerificationToken token) {
        verificationTokenRepository.delete(token);
    }

    /**
     * Generates a cryptographically secure random token
     * using Base64 URL-safe encoding
     * @return a secure random String token
     */

    private String generateSecureToken() {

        // using SecureRandom ensures Tokens aren't predictable

        // create a byte array for the random bytes
        byte[] randomBytes = new byte[tokenLength];
        // Fill with secure random values
        secureRandom.nextBytes(randomBytes);
        // Encode using Base64 URL-safe encoding and return as String
        return Base64 // This means you can embed this token directly in links
                .getUrlEncoder() // choose URL and filename safe Base64 variant
                .withoutPadding() // Drop the trailing "=" characters
                .encodeToString(randomBytes); // performs the conversion and returns your new token
    }
}
