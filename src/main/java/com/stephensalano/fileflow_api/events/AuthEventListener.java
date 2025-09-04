package com.stephensalano.fileflow_api.events;

import com.stephensalano.fileflow_api.services.email.EmailService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Component;
import org.springframework.transaction.event.TransactionPhase;
import org.springframework.transaction.event.TransactionalEventListener;

/**
 * A unified listener for all authentication and user-related application events.
 * This component decouples business logic (e.g., user registration) from
 * side effects (e.g., sending emails).
 *
 * It uses @TransactionalEventListener to ensure actions are only taken after
 * the originating database transaction has successfully committed.
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class AuthEventListener {

    private final EmailService emailService;

    @Async("emailTaskExecutor")
    @TransactionalEventListener(phase = TransactionPhase.AFTER_COMMIT)
    public void handleRegistrationComplete(OnRegistrationCompleteEvent event) {
        log.info("Listener handling registration complete for user: {}", event.getUsername());
        emailService.sendVerificationEmail(event.getEmail(), event.getUsername(), event.getToken());
    }

    @Async("emailTaskExecutor")
    @TransactionalEventListener(phase = TransactionPhase.AFTER_COMMIT)
    public void handleWelcome(OnWelcomeEvent event) {
        log.info("Listener handling welcome event for user: {}", event.getUsername());
        emailService.sendWelcomeEmail(event.getEmail(), event.getUsername());
    }

    @Async("emailTaskExecutor")
    @TransactionalEventListener(phase = TransactionPhase.AFTER_COMMIT)
    public void handlePasswordResetRequest(OnPasswordResetRequestEvent event) {
        log.info("Listener handling password reset request for user: {}", event.getUsername());
        emailService.sendPasswordResetEmail(event.getEmail(), event.getUsername(), event.getToken());
    }

    @Async("emailTaskExecutor")
    @TransactionalEventListener(phase = TransactionPhase.AFTER_COMMIT)
    public void handlePasswordResetSuccess(OnPasswordResetSuccessEvent event) {
        log.info("Listener handling password reset success for user: {}", event.getUsername());
        emailService.sendPasswordResetSuccessEmail(event.getEmail(), event.getUsername());
    }

    @Async("emailTaskExecutor")
    @TransactionalEventListener(phase = TransactionPhase.AFTER_COMMIT)
    public void handlePasswordChange(OnPasswordChangeEvent event){
        log.info("Listener handling password change for user: {}", event.getUsername());
        emailService.sendPasswordChangedSecurityAlert(event.getEmail(), event.getUsername(), event.getSecurityContext());
    }

    @Async("emailTaskExecutor")
    @TransactionalEventListener(phase = TransactionPhase.AFTER_COMMIT)
    public void handleAccountLockout(OnAccountLockoutEvent event) {
        log.info("Listener handling account lockout for user: {}", event.getUsername());
        emailService.sendAccountLockoutEmail(event.getEmail(), event.getUsername(), event.getSecurityContext());
    }

    @Async("emailTaskExecutor")
    @TransactionalEventListener (phase = TransactionPhase.AFTER_COMMIT)
    public void handleAnonymizeAccount(OnAccountAnonymizedEvent event) {
        log.info("Listener handling anonymized account for user: {}", event.getUsername());
        // email service call
        emailService.sendAccountDeletionConfirmationEmail(event.getEmail(), event.getUsername());

    }
}