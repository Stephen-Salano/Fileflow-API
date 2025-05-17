package com.stephensalano.fileflow_api.repository;

import com.stephensalano.fileflow_api.entities.Account;
import com.stephensalano.fileflow_api.entities.TokenTypes;
import com.stephensalano.fileflow_api.entities.VerificationToken;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.expression.spel.ast.OpAnd;

import java.util.Optional;
import java.util.UUID;

public interface VerificationTokenRepository extends JpaRepository<VerificationToken, UUID> {
    Optional<VerificationToken> findByToken(String token);
    Optional<VerificationToken> findByAccountAndTokenTypes(Account account, TokenTypes tokenTypes);
    void deleteByAccount(Account account);

}
