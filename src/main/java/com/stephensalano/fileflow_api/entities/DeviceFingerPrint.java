package com.stephensalano.fileflow_api.entities;

import jakarta.persistence.*;
import lombok.*;

import java.time.LocalDateTime;
import java.util.UUID;

/**
 * Represents a single device/browser fingerprint tied to an account
 * WE store the raw hash, UA string, IP, plus created/last-used timestamps
 */

@Entity
@Table(
        name = "device_fingerprints", uniqueConstraints = {
        @UniqueConstraint(name = "unique_fingerprint", columnNames = {"account_id", "fingerprint_hash"})}
)
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class DeviceFingerPrint {
    // Primary Key
    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    // Owning client
    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "account_id", nullable = false)
    private Account account;

    //Hash of the raw fingerprint data (e.g. canvas + audio + plugins, etc)
    @Column(name = "fingerprint_hash", nullable = false, length = 128)
    private String fingerPrintHash;

    // Full user agent string for debugging/tracking
    @Column(name = "user_agent", nullable = false, length = 512)
    private String userAgent;

    // IP address when this fingerprint was first seen
    @Column(name = "ip_address", nullable = false, length = 45)
    private String ipAddress;

    // When this device was first registered
    @Column(name = "created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt;

    // When this device was last authenticated
    @Column(name = "last_used_at", nullable = false)
    private LocalDateTime lastUsedAt;

    @Column(name = "trusted", nullable = false)
    private boolean trusted = true; // we default to trusted on first login

    @Column(name = "device_type", length = 50)
    private String deviceType; //eg. mobile or desktop

    @Column(name = "browser", length = 100)
    private String browser;

    @Column(name = "os", length = 100)
    private String operatingSystem;


    @PrePersist
    protected void onCreate(){
        this.createdAt = LocalDateTime.now();
        this.lastUsedAt = this.createdAt;
    }

    @PreUpdate
    protected void onUpdate(){
        this.lastUsedAt = LocalDateTime.now();
    }

}
