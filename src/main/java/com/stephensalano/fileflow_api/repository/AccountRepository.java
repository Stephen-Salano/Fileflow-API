package com.stephensalano.fileflow_api.repository;

import com.stephensalano.fileflow_api.entities.Account;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.Optional;
import java.util.UUID;
@Repository
public interface AccountRepository extends JpaRepository<Account, UUID > {
    // Using JOIN FETCH to explicitly load related entities and prevent LazyInitializationException.
    // This is more reliable than @EntityGraph for complex object graphs.
    @Query("SELECT a FROM Account a JOIN FETCH a.user u LEFT JOIN FETCH u.accounts WHERE a.username = :username")
    Optional<Account> findByUsername(@Param("username") String username);
    @Query("SELECT a FROM Account a JOIN FETCH a.user u LEFT JOIN FETCH u.accounts WHERE a.email = :email")
    Optional<Account> findByEmail(@Param("email") String email);
    boolean existsByUsername(String username);
    boolean existsByEmail(String email);
}
