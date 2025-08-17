package com.stephensalano.fileflow_api.events;

import com.stephensalano.fileflow_api.dto.security.SecurityContext;
import com.stephensalano.fileflow_api.entities.Account;
import com.stephensalano.fileflow_api.repository.AccountRepository;
import com.stephensalano.fileflow_api.utils.SecurityUtils;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.event.EventListener;
import org.springframework.security.authentication.event.AuthenticationFailureBadCredentialsEvent;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;
import ua_parser.Client;
import ua_parser.Parser;

@Component
@RequiredArgsConstructor
@Slf4j
public class AuthenticationFailureListener {

    private final AccountRepository accountRepository;
    private final ApplicationEventPublisher eventPublisher;
    private final HttpServletRequest request;
    private final Parser uaParser;

    @Value("${login.app.threshold}")
    private int loginThreshold;

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    @EventListener
    public void handleAuthFailureBadCredentials(AuthenticationFailureBadCredentialsEvent event) {
        String username = event.getAuthentication().getName();
        accountRepository.findByUsername(username).ifPresent(account -> {
            if (account.isAccountNonLocked()){
                // we increment the failed attempts counter
                int newAttemptCounter = account.getFailedLoginAttempts() + 1;
                account.setFailedLoginAttempts(newAttemptCounter);

                log.debug("Failed login attempt #{} for user: {}", newAttemptCounter, username);

                // Check if the threshold has been reached
                if (newAttemptCounter >= loginThreshold){
                    account.setAccountNonLocked(false);
                    // Reset the counter
                    account.setFailedLoginAttempts(0);
                    log.warn("Account for user {} has been locked due to {} failed login attempts", username, loginThreshold);

                    // publish an event send a notification email
                    publishAccountLockoutEvent(account);
                }
                accountRepository.save(account);
            }
        });
    }

    private void publishAccountLockoutEvent(Account account) {
        String ipAddress = SecurityUtils.extractClientIp(request);
        String userAgent = request.getHeader("User-Agent");
        String browser = "Unknown";
        String os = "Unknown";
        String deviceType = "Unknown";

        if (userAgent != null && !userAgent.isBlank()) {
            try {
                Client c = uaParser.parse(userAgent);
                browser = c.userAgent.family;
                os = c.os.family;
                deviceType = c.device.family;
            } catch (Exception e) {
                log.warn("Could not parse User-Agent string during lockout event: {}", userAgent);
            }
        }

        SecurityContext securityContext = new SecurityContext(
                null, // No fingerprint available on failed login
                userAgent,
                ipAddress,
                browser,
                os,
                deviceType
        );

        eventPublisher.publishEvent(new OnAccountLockoutEvent(
                this,
                account.getEmail(),
                account.getUsername(),
                securityContext
        ));
    }
}
