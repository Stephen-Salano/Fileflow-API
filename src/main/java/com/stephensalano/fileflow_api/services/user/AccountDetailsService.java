package com.stephensalano.fileflow_api.services.user;

import com.stephensalano.fileflow_api.entities.Account;
import com.stephensalano.fileflow_api.repository.AccountRepository;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@AllArgsConstructor
@Slf4j
public class AccountDetailsService implements UserDetailsService {

    // DI Account repo
    private final AccountRepository accountRepository;

    @Override
    @Transactional(readOnly = true)
    public UserDetails loadUserByUsername(String usernameOrEmail) throws UsernameNotFoundException {
        log.debug("Loading user details for: {}", usernameOrEmail);

        // Try to find by username first, then by email
        Account account = accountRepository.findByUsername(usernameOrEmail)
                .orElseGet(() -> accountRepository.findByEmail(usernameOrEmail)
                        .orElseThrow(() -> new UsernameNotFoundException(
                                "user not found with username or email: " + usernameOrEmail
                        )));

        log.debug("User found: {}", account.getUsername());
        return account;
    }
}
