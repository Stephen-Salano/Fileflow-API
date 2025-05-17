package com.stephensalano.fileflow_api.repository;

import com.stephensalano.fileflow_api.entities.Account;
import com.stephensalano.fileflow_api.entities.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;
import java.util.UUID;

public interface UserRepository extends JpaRepository<User, UUID> {

    Optional<Account> findAccountsByUserId(UUID id);
}
