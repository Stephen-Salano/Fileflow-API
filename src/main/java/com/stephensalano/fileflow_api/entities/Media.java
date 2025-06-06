package com.stephensalano.fileflow_api.entities;


import jakarta.persistence.*;
import lombok.*;

import java.time.LocalDateTime;
import java.util.UUID;

@Entity
@Table(name = "media_files")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class Media {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "account_id", nullable = false)
    private Account account;

    @Column(name = "file_name", nullable = false)
    private String fileName;

    @Column(name = "original_file_name")
    private String originalFileName;

    @Column(name = "file_path", nullable = false)
    private String filePath;

    @Column(name = "file_type", length = 100)
    private String fileType;

    @Column(name = "file_size")
    private Long fileSize;

    @Column(name = "content_type", length = 100)
    private String contentType;

    @Column(name = "metadata", columnDefinition = "JSONB")
    private String metadata; // JSONB data will be handled as String at entity level

    @Column(name = "width")
    private Integer width;

    @Column(name = "height")
    private Integer height;

    @Column(name = "duration")
    private Integer duration;

    @Column(name = "bit_rate")
    private Integer bitRate;

    @Column(name = "codec", length = 50)
    private String codec;

    @Column(name = "is_original")
    private Boolean isOriginal;

    @Column(name = "public_access")
    private Boolean publicAccess;

    @Column(name = "processing_status", length = 20)
    private String processingStatus;

    @Column(name = "processing_message")
    private String processingMessage;

    @Column(name = "created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt;

    @Column(name = "updated_at", nullable = false)
    private LocalDateTime updatedAt;

    @PrePersist
    protected void onCreate(){
        this.createdAt = LocalDateTime.now();
        this.updatedAt = this.createdAt;
    }

    @PreUpdate
    protected void onUpdate(){
        this.updatedAt = LocalDateTime.now();
    }

}
