package com.stephensalano.fileflow_api.services.email;

import com.stephensalano.fileflow_api.dto.security.SecurityContext;

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
     */
    void sendVerificationEmail(String to, String username, String token);

    void sendWelcomeEmail(String to, String username);

    /**
     * Sends a password reset email with a link containing the reset token
     * @param to the recipient's email address
     * @param username The recipients username
     * @param token the password reset token
     */
    void sendPasswordResetEmail(String to, String username, String token);

    /**
     * Sends a confirmation email after a password has been successfully reset
     * @param to the recipient's email address
     * @param username The recipients username
     */
    void sendPasswordResetSuccessEmail(String to, String username);

    /**
     * Sends a security alert email notifying a user that their password has been changed from a logged-in session.
     *
     * @param to              The recipient's email address.
     * @param username        The recipient's username.
     * @param securityContext Contextual information about the request (IP, browser, etc.).
     */
    void sendPasswordChangedSecurityAlert(String to, String username, SecurityContext securityContext);
}
