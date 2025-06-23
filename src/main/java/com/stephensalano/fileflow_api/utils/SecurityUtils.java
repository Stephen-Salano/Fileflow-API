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
        if (forwarded != null && !forwarded.isBlank()){
            return forwarded.split(",")[0];
        }
        return request.getRemoteAddr();
    }
}
