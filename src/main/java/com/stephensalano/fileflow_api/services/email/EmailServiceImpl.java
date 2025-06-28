package com.stephensalano.fileflow_api.services.email;

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
            // prepare verification link(URL) with token
            Context context = getContext(username, token);

            /*
            Thymeleaf loads your verification-email.html file, replaces the placeholders with the values from context
            and returns a complete HTML string
             */
            String emailContent = templateEngine.process("verification-email", context);

            // Create and send the email
            MimeMessage message = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(
                    message, true, StandardCharsets.UTF_8.name()
            );

            helper.setFrom(fromEmail); // the "no-reply" address or support address
            helper.setTo(to); // the recipient's email
            helper.setSubject(appName + " - Verify your Email"); // a clear, branded subject line
            helper.setText(emailContent, true); // true indicates HTML content

            mailSender.send(message);
            log.info("Verification email sent to: {}", to);
        } catch (MessagingException e){
            log.error("Failed to send verification email to{}: {}", to, e.getMessage());
        }
    }

    private Context getContext(String username, String token) {
        String verificationUrl = frontendUrl + "/verify?token=" + token;

        // Set up the Thymeleaf context with a few variables for the template
            /*
            We are using Thymeleaf's context to pass three values into our HTML template
            - This is how Thymeleaf knows what to fill in
             */
        Context context = new Context();
        context.setVariable("name", username); // so we can say something like "Hi Alice"
        context.setVariable("verificationUrl", verificationUrl); // The link we generated
        context.setVariable("appName", appName); // to brand the email
        return context;
    }

    @Override
    @Async("emailTaskExecutor")
    public void sendWelcomeEmail(String to, String username) {
        try{
            // Set up the Thymeleaf context with variables for the template
            Context context = new Context();
            context.setVariable("name", username);
            context.setVariable("loginUrl", frontendUrl + "/login");
            context.setVariable("appName", appName);

            // Process the HTML template with the context
            String emailContent = templateEngine.process("welcome-email", context);

            // Create and send the email
            MimeMessage message = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(
                    message, true, StandardCharsets.UTF_8.name()
            );

            helper.setFrom(fromEmail);
            helper.setTo(to);
            helper.setSubject("Welcome to " + appName + "!");
            helper.setText(emailContent, true); // true indicates HTML content

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

            Context context = new Context();
            context.setVariable("name", username);
            context.setVariable("resetUrl", resetUrl);
            context.setVariable("appName", appName);

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
            Context context = new Context();
            context.setVariable("name", username);
            context.setVariable("loginUrl", frontendUrl + "/login");
            context.setVariable("appName", appName);

            String emailContent = templateEngine.process("password-reset-success-email", context);

            MimeMessage message = createMimeMessage(to, appName+ " - Your password has been reset", emailContent);
            mailSender.send(message);
            log.info("Password reset confirmation email sent to: {}", to);
        } catch (MessagingException e) {
            log.error("Failed to send password reset confirmation email to {}: {}", to, e.getMessage(), e);
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
}
