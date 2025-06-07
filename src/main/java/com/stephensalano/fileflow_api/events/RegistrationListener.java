package com.stephensalano.fileflow_api.events;

import com.stephensalano.fileflow_api.services.email.EmailService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
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
    public void handleOnRegistrationComplete(OnRegistrationCompleteEvent event){
        String to = event.getEmail();
        String username = event.getUsername();
        String token = event.getToken();

        log.info("RegistrationListener caught OnRegistrationCompleteEvent: sending verification email to {}", to);
        boolean sent = emailService.sendVerificationEmail(to, username, token);

        if (!sent){
            log.warn("Failed to send verification email to {}", event.getEmail());
        }
    }
}
