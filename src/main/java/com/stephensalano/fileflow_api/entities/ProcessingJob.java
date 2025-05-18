package com.stephensalano.fileflow_api.entities;

import jakarta.persistence.*;
import lombok.*;

import java.time.LocalDateTime;
import java.util.UUID;

@Entity
@Table(name = "processing_jobs")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class ProcessingJob {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "media_id", nullable = false)
    private Media media;

    @Column(name = "job_type", length = 50, nullable = false)
    private String jobType;

    @Column(name = "processing_parameters", columnDefinition = "JSONB")
    private String processingParameters;

    @Column(name = "status", length = 20, nullable = false)
    private String status;

    @Column(name = "status_message")
    private String statusMessage;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "result_media_version_id")
    private MediaVersion resultMediaVersion;

    @Column(name = "priority")
    private Integer priority;

    @Column(name = "attempts")
    private Integer attempts;

    @Column(name = "max_attempts")
    private Integer maxAttempts;

    @Column(name = "created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt;

    @Column(name = "updated_at", nullable = false)
    private LocalDateTime updatedAt;

    @Column(name = "started_at")
    private LocalDateTime startedAt;

    @Column(name = "completed_at")
    private LocalDateTime completedAt;

    @PrePersist
    protected void onCreate() {
        this.createdAt = LocalDateTime.now();
        this.updatedAt = this.createdAt;
    }

    @PreUpdate
    protected void onUpdate() {
        this.updatedAt = LocalDateTime.now();
    }
}
