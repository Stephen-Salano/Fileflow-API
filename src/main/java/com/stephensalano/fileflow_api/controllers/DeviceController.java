package com.stephensalano.fileflow_api.controllers;

import com.stephensalano.fileflow_api.dto.responses.DeviceFingerprintResponse;
import com.stephensalano.fileflow_api.entities.Account;
import com.stephensalano.fileflow_api.services.security.DeviceFingerprintService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

import java.util.Map;
import java.util.UUID;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api/v1/auth/devices")
public class DeviceController {
    // TODO: Implement endpoints for listing, trusting, untrusting, and removing devices.
    // These endpoints should interact with DeviceFingerprintService.
    // Example:

    private final DeviceFingerprintService deviceFingerprintService;

    @GetMapping
    public ResponseEntity<Map<String, Object>> listDevices(@AuthenticationPrincipal Account account) {
        var devices = deviceFingerprintService
                .listDevices(account)
                .stream()
                .map(fp -> new DeviceFingerprintResponse(
                        fp.getDeviceType(),
                        fp.getBrowser(),
                        fp.getOperatingSystem(),
                        fp.getCreatedAt(),
                        fp.getLastUsedAt(),
                        fp.isTrusted()
                )).toList();

        return ResponseEntity.status(HttpStatus.OK)
                .body(Map.of(
                        "success", true,
                        "message", "Devices listed successfully:",
                        "data", devices
                ));
    }

    @PostMapping("/{id}/trust")
    public ResponseEntity<Map<String, Object>> trustDevice(@PathVariable UUID fingerprintId, @AuthenticationPrincipal Account account) {
        deviceFingerprintService.trustDevice(account, fingerprintId);
        return ResponseEntity.status(HttpStatus.OK)
                .body(Map.of(
                        "success", true,
                        "message", "Device trusted successfully"
                ));
    }

    @PostMapping("/{id}/untrust")
    public ResponseEntity<Map<String, Object>> untrustDevice(@PathVariable UUID fingerprintId, @AuthenticationPrincipal Account account) {
        deviceFingerprintService.untrustDevice(account, fingerprintId);
        return ResponseEntity.status(HttpStatus.OK)
                .body(Map.of(
                        "success", true,
                        "message", "Device untrusted successfully"
                ));
    }

    @DeleteMapping("/{hash}")
    public ResponseEntity<Map<String, Object>> removeDevice(@PathVariable String fingerprintHash, @AuthenticationPrincipal Account account) {
        deviceFingerprintService.removeDevice(account, fingerprintHash);
        return ResponseEntity.status(HttpStatus.OK)
                .body(Map.of(
                        "success", true,
                        "message", "Device removed successfully"
                ));
    }

}
