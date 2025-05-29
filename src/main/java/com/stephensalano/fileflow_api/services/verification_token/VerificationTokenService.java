package com.stephensalano.fileflow_api.services.verification_token;

import com.stephensalano.fileflow_api.entities.Account;
import com.stephensalano.fileflow_api.entities.TokenTypes;
import com.stephensalano.fileflow_api.entities.VerificationToken;

import java.util.Optional;

public interface VerificationTokenService {

    /**
     * Creates a verification token for a specific account
     * @param account the account to create the token for
     * @param tokenTypes the type of token to create (VERIFICATION, PASSWORD_RESET)
     * @return the created verification token entity
     */
    VerificationToken createToken(Account account, TokenTypes tokenTypes);

    /**
     * Verifies if a token is valid and not expired
     *
     * @param token the token string to validate
     * @return the verification token if valid, empty if not found or expired
     */
    Optional<VerificationToken> validateToken(String token);

    /**
     * Invalidates all tokens of a specific type for an account
     *
     * @param account the account whose tokens should be invalidated
     * @param tokenTypes the type of tokens to invalidate
     */
    void invalidateTokens(Account account, TokenTypes tokenTypes);

    /**
     * Retrieves a verification token by its string value
     *
     * @param token the token string to find
     * @return the verification token if found
     */
    Optional<VerificationToken> findByToken(String token);

    /**
     * Deletes a token after it has been used
     *
     * @param token the token to be deleted
     */
    void deleteToken(VerificationToken token);
}
