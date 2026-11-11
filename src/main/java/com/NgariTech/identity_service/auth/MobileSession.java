package com.NgariTech.identity_service.auth;

import com.NgariTech.identity_service.user.UserAccount;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Index;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.PrePersist;
import jakarta.persistence.PreUpdate;
import jakarta.persistence.Table;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.Instant;
import java.util.UUID;

@Entity
@Table(
        name = "mobile_sessions",
        indexes = {
                @Index(name = "idx_mobile_sessions_user_id", columnList = "user_id"),
                @Index(name = "idx_mobile_sessions_status", columnList = "status"),
                @Index(name = "idx_mobile_sessions_expires_at", columnList = "expires_at")
        }
)
@Getter
@Setter
@NoArgsConstructor
public class MobileSession {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    @Column(nullable = false, updatable = false)
    private UUID id;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "user_id", nullable = false)
    private UserAccount user;

    @Column(nullable = false, length = 100)
    private String clientId;

    @Column(nullable = false, length = 40)
    private String authMethod;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 30)
    private MobileSessionStatus status = MobileSessionStatus.ACTIVE;

    @Column(length = 100)
    private String sourceIp;

    @Column(length = 500)
    private String userAgent;

    @Column(nullable = false, updatable = false)
    private Instant createdAt;

    @Column(nullable = false)
    private Instant expiresAt;

    @Column
    private Instant lastSeenAt;

    @Column
    private Instant revokedAt;

    @Column(nullable = false)
    private Instant updatedAt;

    @PrePersist
    void onCreate() {
        Instant now = Instant.now();
        createdAt = now;
        updatedAt = now;
        if (lastSeenAt == null) {
            lastSeenAt = now;
        }
    }

    @PreUpdate
    void onUpdate() {
        updatedAt = Instant.now();
    }

    public boolean revoke(Instant now) {
        if (status != MobileSessionStatus.ACTIVE) {
            return false;
        }
        status = MobileSessionStatus.REVOKED;
        revokedAt = now;
        lastSeenAt = now;
        return true;
    }

    public boolean expire(Instant now) {
        if (status != MobileSessionStatus.ACTIVE || expiresAt.isAfter(now)) {
            return false;
        }
        status = MobileSessionStatus.EXPIRED;
        lastSeenAt = now;
        return true;
    }
}
