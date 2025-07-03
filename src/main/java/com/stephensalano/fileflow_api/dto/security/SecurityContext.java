package com.stephensalano.fileflow_api.dto.security;

/**
 * This is meant to hold :
 * @param fingerprintHash the fingerprint hash
 * @param userAgent the user agent string
 * @param ipAddress the IP address of the client
 */
public record SecurityContext(
        String fingerprintHash,
        String userAgent,
        String ipAddress,
        String browser,
        String os,
        String deviceType

        /// TODO: Optional later we could expand this to include: Device type, Geo info, Language or timezone
        ) {}
