package com.stephensalano.fileflow_api.dto.responses;

import java.time.LocalDateTime;

public record UserProfileResponse(
        String username,
        String email,
        String role,
        String firstName,
        String secondName,
        String bio,
        String profileImage,
        LocalDateTime createdAt

        // TODO: Remember to add / return user profile image

        ) {
}
