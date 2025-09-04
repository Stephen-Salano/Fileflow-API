package com.stephensalano.fileflow_api.services.email;

import com.stephensalano.fileflow_api.dto.security.SecurityContext;
import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;
import org.thymeleaf.context.Context;
import org.thymeleaf.spring6.SpringTemplateEngine;

import java.nio.charset.StandardCharsets;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

/***
 * Implementation of the EmailService Interface
 * Uses Spring's JavaMailSender to send emails and Thymeleaf for templating
 */


@Service
@RequiredArgsConstructor
@Slf4j
public class EmailServiceImpl implements EmailService{


    private final JavaMailSender mailSender;

    @Qualifier("emailTemplateEngine")
    private final SpringTemplateEngine templateEngine;

    @Value("${spring.application.frontend-url}")
    private String frontendUrl;

    @Value("${spring.mail.username}")
    private String fromEmail;

    @Value("${spring.application.name: FileFlow}")
    private String appName;

    @Override
    @Async("emailTaskExecutor")
    public void sendVerificationEmail(String to, String username, String token) {
        try{
            Context context = createBaseContext(username);
            context.setVariable("verificationUrl", frontendUrl + "/verify?token=" + token);
            String emailContent = templateEngine.process("verification-email", context);
            MimeMessage message = createMimeMessage(to, appName + " - Verify your Email", emailContent);
            mailSender.send(message);
            log.info("Verification email sent to: {}", to);
        } catch (MessagingException e){
            log.error("Failed to send verification email to{}: {}", to, e.getMessage());
        }
    }

    @Override
    @Async("emailTaskExecutor")
    public void sendWelcomeEmail(String to, String username) {
        try{
            Context context = createBaseContext(username);
            context.setVariable("loginUrl", frontendUrl + "/login");

            // Process the HTML template with the context
            String emailContent = templateEngine.process("welcome-email", context);
            MimeMessage message = createMimeMessage(to, "Welcome to " + appName + "!", emailContent);
            mailSender.send(message);
            log.info("Welcome email sent to: {}", to);
        } catch (MessagingException e){
            log.error("Failed to send the welcome email to {}: {}", to, e.getMessage());
        }
    }

    @Override
    @Async("emailTaskExecutor")
    public void sendPasswordResetEmail(String to, String username, String token) {
        try {
            String resetUrl = frontendUrl + "/reset-password?token=" + token;
            Context context = createBaseContext(username);
            context.setVariable("resetUrl", resetUrl);

            String emailContent = templateEngine.process("password-reset-email", context);
            MimeMessage message = createMimeMessage(to, appName + " - Password Reset Request", emailContent);
            mailSender.send(message);
            log.info("Password reset email sent to: {}", to);
        } catch (MessagingException e){
            log.error("Failed to send password reset email to {} : {}", to, e.getMessage(), e);
        }
    }

    @Override
    @Async("emailTaskExecutor")
    public void sendPasswordResetSuccessEmail(String to, String username) {

        try {
            Context context = createBaseContext(username);
            context.setVariable("loginUrl", frontendUrl + "/login");
            String emailContent = templateEngine.process("password-reset-success-email", context);

            MimeMessage message = createMimeMessage(to, appName+ " - Your password has been reset", emailContent);
            mailSender.send(message);
            log.info("Password reset confirmation email sent to: {}", to);
        } catch (MessagingException e) {
            log.error("Failed to send password reset confirmation email to {}: {}", to, e.getMessage(), e);
        }
    }

    @Override
    @Async("emailTaskExecutor")
    public void sendPasswordChangedSecurityAlert(String to, String username, SecurityContext securityContext) {
        try {
            // The reset URL is included in case the user did NOT make this change
            String resetUrl = frontendUrl + "/forgot-password";

            Context context = createBaseContext(username);
            context.setVariable("securityContext", securityContext);
            context.setVariable("resetUrl", resetUrl);
            context.setVariable("changeTime", LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss 'UTC'")));

            String emailContent = templateEngine.process("password-changed-alert-email", context);

            MimeMessage message = createMimeMessage(
                    to,
                    "Security Alert: Your " + appName + " Password Was Changed",
                    emailContent
            );
            mailSender.send(message);
            log.info("Password change security alert sent to: {}", to);
        } catch (MessagingException e) {
            log.error("Failed to send password change security alert to {}: {}", to, e.getMessage(), e);
        }
    }

    @Override
    @Async("emailTaskExecutor")
    public void sendAccountLockoutEmail(String to, String username, SecurityContext securityContext) {

        try {
            // The reset URL
            String resetUrl = frontendUrl + "/forgot-password";

            Context context = createBaseContext(username);
            context.setVariable("securityContext", securityContext);
            context.setVariable("resetUrl", resetUrl);
            context.setVariable("lockoutTime", LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss 'UTC'")));

            String emailContent = templateEngine.process("account-lockout-email", context);
            MimeMessage message = createMimeMessage(
                    to,
                    "Security Alert: Your " + appName + " Account Has Been Locked",
                    emailContent
            );
            mailSender.send(message);
            log.info("Account lockout email sent to: {}", to);
        } catch (MessagingException e) {
            log.error("Failed to send account lockout email to {}: {}", to, e.getMessage(), e);
        }
    }

    @Override
    @Async("emailTaskExecutor")
    public void sendAccountDeletionConfirmationEmail(String to, String username) {
        try{

            Context context = createBaseContext(username);
            // processing the HTML template
            String emailContent = templateEngine.process("account-deleted-email", context);
            MimeMessage message = createMimeMessage(to, "Your " + appName + " Account Has Been Deleted", emailContent);
            mailSender.send(message);
            log.info("Account deletion confirmation email sent to: {}", to);
        } catch (MessagingException e) {
            log.error("Failed to send account deletion email to {}: {}", to, e.getMessage(), e);
        }

    }

    // Helper method for message creation
    private MimeMessage createMimeMessage(String to, String subject, String emailContent) throws MessagingException {
        MimeMessage message = mailSender.createMimeMessage();
        MimeMessageHelper helper = new MimeMessageHelper(
                message, true, StandardCharsets.UTF_8.name()
        );
        helper.setFrom(fromEmail);
        helper.setTo(to);
        helper.setSubject(subject);
        helper.setText(emailContent, true);
        return message;
    }

    private Context createBaseContext(String username) {
        Context context = new Context();
        context.setVariable("name", username);
        context.setVariable("appName", appName);
        return context;
    }
}
