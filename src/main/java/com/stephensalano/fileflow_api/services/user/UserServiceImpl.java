package com.stephensalano.fileflow_api.services.user;

import com.stephensalano.fileflow_api.configs.security.JwtService;
import com.stephensalano.fileflow_api.dto.requests.ChangePasswordRequest;
import com.stephensalano.fileflow_api.dto.responses.UserProfileResponse;
import com.stephensalano.fileflow_api.dto.security.SecurityContext;
import com.stephensalano.fileflow_api.entities.Account;
import com.stephensalano.fileflow_api.entities.User;
import com.stephensalano.fileflow_api.events.OnPasswordChangeEvent;
import com.stephensalano.fileflow_api.repository.AccountRepository;
import com.stephensalano.fileflow_api.utils.SecurityUtils;
import com.stephensalano.fileflow_api.utils.ValidationUtils;
import lombok.RequiredArgsConstructor;
import org.springframework.cache.annotation.CacheEvict;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.cache.annotation.Caching;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import jakarta.servlet.http.HttpServletRequest;
import ua_parser.Client;
import ua_parser.Parser;

@Service
@RequiredArgsConstructor
@Slf4j
public class UserServiceImpl implements UserService {


    private final AccountRepository accountRepository;
    private final PasswordEncoder passwordEncoder;
    private final HttpServletRequest request;
    private final JwtService jwtService;
    private final ApplicationEventPublisher eventPublisher;
    private final Parser uaParser;


    @Override
    @Transactional
    @Caching(evict = {
            @CacheEvict(value = "users", key = "#authenticatedAccount.username"),
            @CacheEvict(value = "users", key = "#authenticatedAccount.email")
    })
    public void changePassword(Account authenticatedAccount, ChangePasswordRequest changePasswordRequest) {

        // verify the current password
        if (!passwordEncoder.matches(changePasswordRequest.currentPassword(), authenticatedAccount.getPassword())) {
            throw new IllegalArgumentException("Incorrect current password");
        }
        // Validate the new passwords match
        ValidationUtils.validatePasswordsMatch(changePasswordRequest.newPassword(), changePasswordRequest.confirmPassword());

        // Encode and update
        String encodedPassword = passwordEncoder.encode(changePasswordRequest.newPassword());
        // Set it to the account entity
        authenticatedAccount.setPassword(encodedPassword);
        accountRepository.save(authenticatedAccount);

        // Publish notification event
        publishPasswordChangedNotification(authenticatedAccount);
    }

    private void publishPasswordChangedNotification(Account account) {
        String ipAddress = SecurityUtils.extractClientIp(request);
        String fingerPrintHash = extractFingerprintHash();
        String userAgent = request.getHeader("User-Agent");
        String browser = "Unknown";
        String os = "Unknown";
        String deviceType = "Unknown";

        if (userAgent != null && !userAgent.isBlank()){
            try{
                Client c = uaParser.parse(userAgent);
                browser = c.userAgent.family;
                os = c.os.family;
                deviceType = c.device.family;
            } catch (Exception e){
                log.warn("Could not parse User-Agent string: {}", userAgent);
            }
        }
        SecurityContext securityContext = new SecurityContext(
                fingerPrintHash,
                userAgent,
                ipAddress,
                browser,
                os,
                deviceType
        );

        eventPublisher.publishEvent(
                new OnPasswordChangeEvent(
                        this,
                        account.getEmail(),
                        account.getUsername(),
                        securityContext
                )
        );
        log.info("Published OnPasswordChangedEvent for user: {}", account.getUsername());
    }

    @Cacheable(value = "user-profiles", key = "#authenticatedAccount.username")
    @Override
    public UserProfileResponse getUserProfile(Account authenticatedAccount) {
        // Getting the user details from the account object
        User authenticatedUser = authenticatedAccount.getUser();

        // Handling nul profile image by creating a url if it exists
        String profileImageUrl = (authenticatedUser.getProfileImage() != null)
                ? "/api/v1/media/file/" + authenticatedUser.getProfileImage().getId() : null;
        return new UserProfileResponse(
                authenticatedAccount.getUsername(),
                authenticatedAccount.getEmail(),
                authenticatedAccount.getRole().name(),
                authenticatedUser.getFirstName(),
                authenticatedUser.getSecondName(),
                authenticatedUser.getBio(),
                profileImageUrl,
                authenticatedAccount.getCreatedAt()
        );

    }

    private String extractFingerprintHash() {
        final String authHeader = request.getHeader("Authorization");

        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return null; // No token present, nothing to clean up.
        }
        final String token = authHeader.substring(7);
        try {
            return jwtService.extractFingerprintHash(token);
        } catch (Exception e) {
            log.warn("Could not extract fingerprint from token during password update: {}", e.getMessage());
            return null;
        }

    }
}