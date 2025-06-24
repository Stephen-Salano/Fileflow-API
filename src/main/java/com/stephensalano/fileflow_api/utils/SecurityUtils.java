package com.stephensalano.fileflow_api.utils;

import jakarta.servlet.http.HttpServletRequest;

/**
 * IP address extraction logic
 */
public class SecurityUtils {
    /**
     * Extracts the real client IP from the request
     * considering possible proxies or load balancers
     */
    public static String extractClientIp(HttpServletRequest request){
        String forwarded = request.getHeader("X-Forwarded-For");
        return (forwarded != null && !forwarded.isBlank())
                ? forwarded.split(",")[0]
                : request.getRemoteAddr();
    }
}
