package com.stephensalano.fileflow_api.events;

import com.stephensalano.fileflow_api.services.email.EmailService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Component;
import org.springframework.transaction.event.TransactionPhase;
import org.springframework.transaction.event.TransactionalEventListener;

/**
 * Listens fo OnRegistrationCompleteEvent and sends out the verification email
 * Because this listener is not wrapped in the original AuthService transaction
 * sending mail won't interfere with JPA's commit or timeout
 */

@Component
@RequiredArgsConstructor
@Slf4j
public class RegistrationListener {

    private final EmailService emailService;

    /**
     * using `@TransactionEventListener(phase = TransactionPhase.AFTER_COMMIT)
     *
     * This ensures that sending the verification email happens only after the registerUser() transaction has committed
     * @param event
     */
    @TransactionalEventListener(phase = TransactionPhase.AFTER_COMMIT)
    @Async("emailTaskExecutor")
    public void handleOnRegistrationComplete(OnRegistrationCompleteEvent event){
        try{
            log.info("Async listener running in thread: {}", Thread.currentThread().getName());
            emailService.sendVerificationEmail(
                    event.getEmail(),
                    event.getUsername(),
                    event.getToken()
            );
        } catch (Exception e) {
            log.error("Failed to send verification email to {}: {}", event.getEmail(), e.getMessage());
        }
    }

    @Async("emailTaskExecutor")
    @TransactionalEventListener(phase = TransactionPhase.AFTER_COMMIT)
    public void handleOnWelcome(OnWelcomeEvent event){

        try {
            emailService.sendWelcomeEmail(
                    event.getEmail(),
                    event.getUsername()
            );
        } catch (Exception e) {
            log.error("Failed to send Welcome email to {}: {}", event.getEmail(), e.getMessage());
        }
    }
}
