package com.stephensalano.fileflow_api.dto.requests;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record PasswordResetRequest(
        @NotBlank(message = "Token cannot be blank")
        String token,
        @NotBlank(message = "Password cannot be blank")
        @Size(min = 8, message = "Password must be at least 8 characters long")
        String newPassword,
        @NotBlank(message = "Confirm password cannot be blank")
        String confirmPassword
) {
}
