package com.stephensalano.fileflow_api.repository;

import com.stephensalano.fileflow_api.entities.Account;
import com.stephensalano.fileflow_api.entities.RefreshToken;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.Optional;
import java.util.UUID;

@Repository
public interface RefreshTokenRepository extends JpaRepository<RefreshToken, UUID> {
    Optional<RefreshToken> findByToken(String token);
    Optional<RefreshToken> findByAccount(Account account);
    void deleteByAccount(Account account);

    @Modifying
    @Query("UPDATE RefreshToken rt SET rt.invalidated = true WHERE rt.account = :account")
    void invalidateAllByAccount(Account account);
}
