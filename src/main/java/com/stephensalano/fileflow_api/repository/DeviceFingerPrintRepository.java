package com.stephensalano.fileflow_api.repository;

import com.stephensalano.fileflow_api.entities.Account;
import com.stephensalano.fileflow_api.entities.DeviceFingerPrint;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface DeviceFingerPrintRepository extends JpaRepository<DeviceFingerPrint, UUID> {

    /**
     * Find a sngle fingerprint record for a given account + fingerprint hash.
     * Used to detect known vs new devices
     */
    Optional<DeviceFingerPrint> findByAccountAndFingerPrintHash(Account account, String fingerprintHash);

    // List all devices ever used by this account
    List<DeviceFingerPrint> findAllByAccount(Account account);
}
