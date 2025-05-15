package com.stephensalano.fileflow_api.entities;

import jakarta.persistence.*;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.*;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.time.LocalDateTime;
import java.util.*;
import java.util.stream.Collectors;

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

    @Column(nullable = false)
    @NotBlank(message = "Email cannot be blank")
    @Email(regexp = "^(?=.{1,64}@)[A-Za-z0-9_-+]+(\\\\.[A-Za-z0-9_-+]+)*@[^-][A-Za-z0-9-+]+(\\\\.[A-Za-z0-9-+]+)*(\\\\.[A-Za-z]{2,})$")
    private String email;

    @Column(name = "first_name")
    private String firstName;

    @Column(name = "second_name")
    private String secondName;

    @Column(name = "bio")
    private String bio;

    @ManyToOne(fetch = FetchType.LAZY, optional = true)
    @JoinColumn(name = "profile_image_id")
    private Media profileImage;

    @OneToMany(
            mappedBy = "user",
            cascade = {CascadeType.PERSIST, CascadeType.MERGE, CascadeType.REFRESH, CascadeType.DETACH},
            orphanRemoval = false,
            fetch = FetchType.LAZY
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
        this.email = "anonymized" + UUID.randomUUID() + "@anonymized.com";
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
