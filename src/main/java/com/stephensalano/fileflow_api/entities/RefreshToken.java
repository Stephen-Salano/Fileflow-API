package com.stephensalano.fileflow_api.entities;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.Instant;
import java.time.LocalDateTime;
import java.util.UUID;

@Entity
@Table(name = "refresh_tokens")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class RefreshToken{

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @JoinColumn(name = "account_id", nullable = false, referencedColumnName = "id")
    @ManyToOne(optional = false)
    private Account account;

    @Column(name = "token", nullable = false)
    private String token;

    @Column(name = "expiry_date")
    private Instant expiryDate;

    @Column(name = "invalidated")
    private boolean invalidated;

    @Column(name = "created_at")
    private LocalDateTime createdAt;

    public boolean isExpired(){
        return expiryDate.isBefore(Instant.now());
    }
    
}
