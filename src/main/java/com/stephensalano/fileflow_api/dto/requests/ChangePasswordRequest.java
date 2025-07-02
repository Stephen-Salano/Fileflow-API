package com.stephensalano.fileflow_api.dto.requests;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

/**
 * This DT is used by authenticated users requesting password update without logging them out
 * @param currentPassword the current users password
 * @param newPassword the new password the user wants to set
 * @param confirmPassword the new password the user wants to confirm
 */
public record ChangePasswordRequest(
        @NotBlank(message = "Current password is required")
        String currentPassword,
        @NotBlank(message = "New password is required")
        @Size(min = 8, max = 20, message = "Password must be between 8 to 20 characters")
        @Pattern(regexp =  "^(?=.*[0-9])(?=.*[a-z])(?=.*[A-Z])(?=.*[!@#$%^&+=])(?=\\S+$).{8,20}$")
        String newPassword,
        @NotBlank(message = "Confirm password is required")
        String confirmPassword
) {
}
