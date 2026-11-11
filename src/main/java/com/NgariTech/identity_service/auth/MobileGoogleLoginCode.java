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
import jakarta.persistence.Table;
import jakarta.persistence.UniqueConstraint;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.Instant;
import java.util.UUID;

@Entity
@Table(
        name = "mobile_google_login_codes",
        uniqueConstraints = @UniqueConstraint(
                name = "uk_mobile_google_login_codes_code_hash",
                columnNames = "code_hash"
        ),
        indexes = {
                @Index(name = "idx_mobile_google_login_codes_user_id", columnList = "user_id"),
                @Index(name = "idx_mobile_google_login_codes_expires_at", columnList = "expires_at")
        }
)
@Getter
@Setter
@NoArgsConstructor
public class MobileGoogleLoginCode {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    @Column(nullable = false, updatable = false)
    private UUID id;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "user_id", nullable = false)
    private UserAccount user;

    @Column(nullable = false, unique = true, length = 128)
    private String codeHash;

    @Column(nullable = false, length = 512)
    private String redirectUri;

    @Column(nullable = false)
    private Instant expiresAt;

    @Column
    private Instant consumedAt;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 30)
    private MobileGoogleLoginCodeStatus status = MobileGoogleLoginCodeStatus.ACTIVE;

    @Column(nullable = false, updatable = false)
    private Instant createdAt;

    @PrePersist
    void onCreate() {
        createdAt = Instant.now();
    }

    public boolean isUsableAt(Instant now) {
        return status == MobileGoogleLoginCodeStatus.ACTIVE
                && consumedAt == null
                && expiresAt != null
                && now.isBefore(expiresAt);
    }

    public void consume(Instant now) {
        status = MobileGoogleLoginCodeStatus.USED;
        consumedAt = now;
    }

    public void expire() {
        status = MobileGoogleLoginCodeStatus.EXPIRED;
    }
}
