package com.stephensalano.fileflow_api.entities;

import jakarta.persistence.*;
import lombok.*;

import java.time.LocalDateTime;
import java.util.*;

@Builder
@NoArgsConstructor
@AllArgsConstructor
@Entity
@Table(name = "users")
@Getter
@Setter
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Column(name = "first_name")
    private String firstName;

    @Column(name = "second_name")
    private String secondName;

    @Column(name = "bio")
    private String bio;

    @ManyToOne(fetch = FetchType.EAGER, optional = true)
    @JoinColumn(name = "profile_image_id")
    private Media profileImage;

    @OneToMany(
            mappedBy = "user",
            cascade = {CascadeType.PERSIST, CascadeType.MERGE, CascadeType.REFRESH, CascadeType.DETACH},
            orphanRemoval = false, // We don't want to delete accounts when a user is deleted
            fetch = FetchType.LAZY // Eagerly fetch accounts to prevent LazyInitializationException
    )
    private List<Account> accounts = new ArrayList<>();

    @Column(nullable = false)
    private boolean isDeleted = false;

    @Column(nullable = false, updatable = false)
    private LocalDateTime createdAt;

    @Column(nullable = false)
    private LocalDateTime updatedAt;


    // This sets the uploaded At automatically
    @PrePersist
    protected void onCreate(){
        createdAt = LocalDateTime.now();
        this.updatedAt = createdAt;
    }

    @PreUpdate
    protected void onUpdate(){
        this.updatedAt = LocalDateTime.now();
    }

    /**
     * Anonymizes user data for GDPR compliance without deleting the entity
     * This allows account relationships to remain intact while removing personal data
     */
    public void anonymize(){
        this.firstName = null;
        this.secondName = null;
        this.bio = null;
        this.profileImage = null;
        this.isDeleted = true;

        // break bidirectional relationship but don't delete accounts
        for (Account account: new ArrayList<>(this.accounts)){
            account.setAnonymized(true);
        }
    }

}
