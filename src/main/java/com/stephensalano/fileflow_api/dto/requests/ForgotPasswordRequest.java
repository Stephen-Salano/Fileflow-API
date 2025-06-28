package com.stephensalano.fileflow_api.dto.requests;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;

public record ForgotPasswordRequest(
        @NotBlank(message = "Email cannot be blank")
        @Email(message = "Please provide a valid email address")
        String email
) {
}
