package com.stephensalano.fileflow_api.controllers;

import com.stephensalano.fileflow_api.dto.requests.ChangePasswordRequest;
import com.stephensalano.fileflow_api.dto.responses.UserProfileResponse;
import com.stephensalano.fileflow_api.entities.Account;
import com.stephensalano.fileflow_api.services.user.UserService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api/v1/users")
@RequiredArgsConstructor
@Slf4j
public class UserController {

    private final UserService userService;

    @PutMapping("/me/change-password")
    public ResponseEntity<Map<String, Object>> changePassword(
            @Valid @RequestBody ChangePasswordRequest changePasswordRequest,
            Authentication authentication
            ) {
        // By the time this code runs, Spring security has already confirmed the user
        log.info("Change password attempt for user: {}", authentication.getName());
        // We can safely cast the principal to our Account object
        Account authenticatedAccount = (Account) authentication.getPrincipal();
        // The try-catch is simplified because GlobalExceptionHandler will handle the exceptions
        userService.changePassword(authenticatedAccount, changePasswordRequest);

        log.info("Password change successful for user: {}", authentication.getName());

        return ResponseEntity.ok(Map.of(
                "success", true,
                "message", "Password changed successfully"
        ));
    }
    @GetMapping("/me")
    public ResponseEntity<UserProfileResponse> getCurrentUserDetails(
            Authentication authentication
    ){
        log.info("Getting current user details attempt for user: {}", authentication.getName());
        Account authenticatedAccount = (Account)  authentication.getPrincipal();
        UserProfileResponse userProfile = userService.getUserProfile(authenticatedAccount);
        log.info("Current user details successfull for user: {}", authentication.getName());
        return ResponseEntity.ok(userProfile);

        }

}
