package com.stephensalano.fileflow_api.events;

import com.stephensalano.fileflow_api.repository.AccountRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.cache.annotation.CacheEvict;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.event.EventListener;
import org.springframework.security.authentication.event.AuthenticationSuccessEvent;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

@Component
@RequiredArgsConstructor
@Slf4j
public class AuthenticationSuccessListener {
    private final AccountRepository accountRepository;

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    @EventListener
    @CacheEvict(value = "users", key = "#event.authentication.name")
    public void handleAuthenticationSuccess(AuthenticationSuccessEvent event) {
        String username = event.getAuthentication().getName();
        accountRepository.findByUsername(username).ifPresent(account -> {
            if (account.getFailedLoginAttempts() > 0) {
                account.setFailedLoginAttempts(0);
                accountRepository.save(account);
                log.info("Successfully reset failed login attempts for user: {}", username);
            }
        });
    }

}
