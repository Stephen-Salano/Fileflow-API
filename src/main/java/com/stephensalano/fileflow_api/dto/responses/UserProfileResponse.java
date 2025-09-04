package com.stephensalano.fileflow_api.dto.responses;

import java.time.LocalDateTime;
import java.util.UUID;

public record UserProfileResponse(
        UUID id,
        String username,
        String email,
        String firstName,
        String secondName,
        String bio,
        String profileImageUrl, // Can be null
        String role,
        LocalDateTime createdAt
) {
}