package com.stephensalano.fileflow_api.services.email;

/**
 * Service responsible for sending emails to user
 */
public interface EmailService {

    /**
     * Sends a verification email to a user with a link containing their verification token
     *
     * @param to the recipient's email address
     * @param username The recipients username
     * @param token the verification token
     * @return true if the email was sent successfully, false otherwise
     */
    void sendVerificationEmail(String to, String username, String token);

    void sendWelcomeEmail(String to, String username);
}
