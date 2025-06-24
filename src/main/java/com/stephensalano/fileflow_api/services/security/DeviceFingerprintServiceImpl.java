package com.stephensalano.fileflow_api.services.security;

import com.stephensalano.fileflow_api.dto.requests.DeviceFingerprintRequest;
import com.stephensalano.fileflow_api.entities.Account;
import com.stephensalano.fileflow_api.entities.DeviceFingerPrint;
import com.stephensalano.fileflow_api.exceptions.ResourceNotFoundException;
import com.stephensalano.fileflow_api.repository.DeviceFingerPrintRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import ua_parser.Parser;

import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;

/**
 * Async implementation for managing device fingerprints
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class DeviceFingerprintServiceImpl implements DeviceFingerprintService{

    private final DeviceFingerPrintRepository repository;
    private final Parser parser = new Parser(); // the ua parser instance

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

            // Parse the User-Agent once
            var client = parser.parse(request.userAgent());
            String deviceType = client.device.family; // eg iphone or desktop
            String browser = client.userAgent.family; // eg chrome or iphone
            String operatingSystem = client.os.family; // eg ios or android

            Optional<DeviceFingerPrint> existing = repository
                    .findByAccountAndFingerPrintHash(account, request.fingerprintHash());

            DeviceFingerPrint fingerPrint = existing.map(fp -> {
                fp.setUserAgent(request.userAgent());
                fp.setDeviceType(deviceType);
                fp.setBrowser(browser);
                fp.setOperatingSystem(operatingSystem);
                log.debug("Device already known. Updating lastUsedAt. ID={}", fp.getId());
                return repository.save(fp); // lastUsedAt is handled by the preupdate
            }).orElseGet(() -> {

                DeviceFingerPrint newFingerPrint = DeviceFingerPrint.builder()
                        .account(account)
                        .fingerPrintHash(request.fingerprintHash())
                        .userAgent(request.userAgent())
                        .ipAddress(request.ipAddress())
                        .deviceType(deviceType)
                        .browser(browser)
                        .operatingSystem(operatingSystem)
                        .trusted(true)
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

    @Override
    @Transactional
    public void trustDevice(Account account, UUID fingerprintId) {
        var fp = repository.findById(fingerprintId)
                .filter(d -> d.getAccount().equals(account))
                .orElseThrow(() -> new ResourceNotFoundException("Device fingerprint not found"));
        fp.setTrusted(true);
        repository.save(fp);
    }

    @Override
    @Transactional
    public void untrustDevice(Account account, UUID fingerprintId) {
        var fp = repository.findById(fingerprintId)
                .filter(d -> d.getAccount().equals(account))
                .orElseThrow(() -> new ResourceNotFoundException("Device fingerprint not found"));
        repository.updateTrustedStatus(account, fp.getFingerPrintHash(), false);
    }

    @Override
    public void removeDevice(Account account, String fingerprintHash) {
        repository.findByAccountAndFingerPrintHash(account, fingerprintHash).ifPresent(repository::delete);

    }
}
