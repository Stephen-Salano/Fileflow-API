package com.stephensalano.fileflow_api.repository;

import com.stephensalano.fileflow_api.entities.Account;
import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;
import java.util.UUID;
@Repository
public interface AccountRepository extends JpaRepository<Account, UUID > {
    @EntityGraph(attributePaths = "user") // Telling the repo to also fetch user data at the same time
    Optional<Account> findByUsername(String username);
    @EntityGraph(attributePaths = "user")// Telling the repo to also fetch user data at the same time
    Optional<Account> findByEmail(String email);
    boolean existsByUsername(String username);
    boolean existsByEmail(String email);
}
