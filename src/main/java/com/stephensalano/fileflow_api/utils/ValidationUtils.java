package com.stephensalano.fileflow_api.utils;

import org.springframework.util.StringUtils;

public class ValidationUtils {
    public static void validatePasswordsMatch(String password, String confirmPassword) {
        if (!StringUtils.hasText(password) || !password.equals(confirmPassword)){
            throw new IllegalArgumentException("Passwords do not match.");
        }
    }
}
