package com.stephensalano.fileflow_api.dto.requests;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

public record DeleteAccountRequest(
        @NotBlank(message = "Password field must not be blank")
        @Size(min = 8, max = 20, message = "Password must be between 8 to 20 characters")
        @Pattern(regexp =  "^(?=.*[0-9])(?=.*[a-z])(?=.*[A-Z])(?=.*[!@#$%^&+=])(?=\\S+$).{8,20}$",
                message = "Password must contain at least one digit, one lowercase letter, one uppercase character and no whitespace")
        String password
) {
}
