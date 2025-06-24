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
        // Check various headers that might contain the real IP
        String[] headers = {
                "X-Forwarded-For",
                "X-Real-IP",
                "X-Forwarded",
                "Forwarded-For",
                "Forwarded"
        };

        for (String header : headers) {
            String ip = request.getHeader(header);
            if (ip != null && !ip.isBlank() && !ip.equalsIgnoreCase("unknown")) {
                // Take the first IP if there are multiple (comma-separated)
                return ip.split(",")[0].trim();
            }
        }

        // Fallback to remote address
        String remoteAddr = request.getRemoteAddr();

        // Normalize localhost addresses
        if ("0:0:0:0:0:0:0:1".equals(remoteAddr) || "::1".equals(remoteAddr)) {
            return "127.0.0.1";  // Convert IPv6 localhost to IPv4
        }

        return remoteAddr;
    }
}