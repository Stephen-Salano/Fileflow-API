package com.stephensalano.fileflow_api.dto.responses;



import java.time.LocalDateTime;

public record DeviceFingerprintResponse(
        String deviceType,
        String browser,
        String operatingSystem,
        LocalDateTime createdAt,
        LocalDateTime lastUsedAt,
        boolean trusted
) {
}
