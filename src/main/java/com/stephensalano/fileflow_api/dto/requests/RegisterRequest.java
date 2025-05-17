package com.stephensalano.fileflow_api.dto.requests;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

public record RegisterRequest(
        @NotBlank(message = "Email cannot be blank")
        @Email(regexp = "^(?=.{1,64}@)[A-Za-z0-9_-+]+(\\\\.[A-Za-z0-9_-+]+)*@[^-][A-Za-z0-9-+]+(\\\\.[A-Za-z0-9-+]+)*(\\\\.[A-Za-z]{2,})$")
        String email,

        @NotBlank(message = "Username must not be blank")
        String username,

        @NotBlank(message = "Password field must not be blank")
        @Size(min = 8, max = 20, message = "Password must be between 8 to 20 characters")
        @Pattern(regexp =  "^(?=.*[0-9])(?=.*[a-z])(?=.*[A-Z])(?=.*[@#$%^&+=])(?=\\S+$).{8,20}$",
        message = "Password must contain at least one digit, one lowercase letter, one uppercase character and no whitespace")
        String password,

        String firstname,
        String lastname

) {
}
