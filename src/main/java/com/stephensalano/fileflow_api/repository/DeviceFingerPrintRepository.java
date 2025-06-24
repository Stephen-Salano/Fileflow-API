package com.stephensalano.fileflow_api.repository;

import com.stephensalano.fileflow_api.entities.Account;
import com.stephensalano.fileflow_api.entities.DeviceFingerPrint;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface DeviceFingerPrintRepository extends JpaRepository<DeviceFingerPrint, UUID> {

    /**
     * Find a single fingerprint record for a given account + fingerprint hash.
     * Used to detect known vs new devices
     */
    Optional<DeviceFingerPrint> findByAccountAndFingerPrintHash(Account account, String fingerprintHash);

    // List all devices ever used by this account
    List<DeviceFingerPrint> findAllByAccount(Account account);

    @Modifying
    @Query("UPDATE DeviceFingerPrint d SET d.trusted = :trusted WHERE d.account = :account AND d.fingerPrintHash = :hash")
    @Transactional
    void updateTrustedStatus(Account account, String hash, boolean trusted);
}
