package com.stephensalano.fileflow_api.dto.requests;

/**
 * Represents the dTO for a device fingerprint request
 * This record encapsulates the necessary information collected from the client's device
 * to identify it uniquely
 *
 * @param fingerprintHash A unique hash generated from various browser and device attributes
 * @param userAgent The user-agent string of the client's browser
 * @param ipAddress The IP address of the client making the request
 */
public record DeviceFingerprintRequest(
        String fingerprintHash,
        String userAgent,
        String ipAddress,
        String browser,
        String os,
        String deviceType
) {
}
