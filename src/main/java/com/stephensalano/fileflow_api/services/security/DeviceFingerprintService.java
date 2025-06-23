package com.stephensalano.fileflow_api.services.security;

import com.stephensalano.fileflow_api.dto.requests.DeviceFingerprintRequest;
import com.stephensalano.fileflow_api.entities.Account;
import com.stephensalano.fileflow_api.entities.DeviceFingerPrint;

import java.util.List;
import java.util.concurrent.CompletableFuture;

/**
 * Asynchronous Service for managing device fingerprint per account
 */
public interface DeviceFingerprintService {

    /**
     * Registers or updates a device fingerprint asynchronously
     * @param account the authenticated account
     * @param request the fingerprint data
     * @return a future with the created or updated fingerprint
     */
    CompletableFuture<DeviceFingerPrint> registerFingerprint(Account account, DeviceFingerprintRequest request);

    /**
     * Checks if the given fingerprint is already known for this account
     * @param account the account
     * @param fingerprintHash the device fingerprint hash
     * @return true if known
     */
    boolean isKnownDevice(Account account, String fingerprintHash);

    /**
     * Lists all fingerprints for the given account.
     * @param account the account
     * @return list of known fingerprints
     */
    List<DeviceFingerPrint> listDevices(Account account);
}
