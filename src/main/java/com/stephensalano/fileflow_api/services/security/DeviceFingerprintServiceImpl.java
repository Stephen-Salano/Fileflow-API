package com.stephensalano.fileflow_api.services.security;

import com.stephensalano.fileflow_api.dto.requests.DeviceFingerprintRequest;
import com.stephensalano.fileflow_api.entities.Account;
import com.stephensalano.fileflow_api.entities.DeviceFingerPrint;
import com.stephensalano.fileflow_api.repository.DeviceFingerPrintRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;

/**
 * Async implementation for managing device fingerprints
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class DeviceFingerprintServiceImpl implements DeviceFingerprintService{

    private final DeviceFingerPrintRepository repository;

    /**
     * Asynchronously update or register a fingerprint
     *
     * @param account the authenticated account
     * @param request the fingerprint data
     * @return a future with the created or updated fingerprint
     */
    @Override
    @Async
    @Transactional
    public CompletableFuture<DeviceFingerPrint> registerFingerprint(Account account, DeviceFingerprintRequest request) {
        try{
            log.debug("Async registration: account={}, hash={}", account.getId(), request.fingerprintHash());

            Optional<DeviceFingerPrint> existing = repository.findByAccountAndFingerPrintHash(account, request.fingerprintHash());

            DeviceFingerPrint fingerPrint = existing.map(fp -> {
                log.debug("Device already known. Updating lastUsedAt. ID={}", fp.getId());
                return repository.save(fp); // lastUsedAt is handled by the preupdate
            }).orElseGet(() -> {

                DeviceFingerPrint newFingerPrint = DeviceFingerPrint.builder()
                        .account(account)
                        .fingerPrintHash(request.fingerprintHash())
                        .userAgent(request.userAgent())
                        .ipAddress(request.ipAddress())
                        .build();
                log.debug("New device. Saving fingerprint for account={}", account.getId());
                return repository.save(newFingerPrint);
            });
            return CompletableFuture.completedFuture(fingerPrint);
        } catch (Exception e){
            log.error("Failed to register device fingerprint asynchronously for account {}:{}", account.getId(), e.getMessage(), e);
            return CompletableFuture.failedFuture(e);
        }
    }

    /**
     * Checks if the given fingerprint is already known for this account
     * @param account the account
     * @param fingerprintHash the device fingerprint hash
     * @return true if known
     */
    @Override
    public boolean isKnownDevice(Account account, String fingerprintHash) {
        return repository.findByAccountAndFingerPrintHash(account, fingerprintHash).isPresent();
    }

    /**
     * Lists all fingerprints for the given account.
     * @param account the account
     * @return list of known fingerprints
     */
    @Override
    public List<DeviceFingerPrint> listDevices(Account account) {
        return repository.findAllByAccount(account);
    }
}
