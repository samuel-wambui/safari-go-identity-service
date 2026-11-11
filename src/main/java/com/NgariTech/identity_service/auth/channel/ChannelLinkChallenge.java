package com.NgariTech.identity_service.auth.channel;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Index;
import jakarta.persistence.PrePersist;
import jakarta.persistence.Table;
import jakarta.persistence.UniqueConstraint;
import jakarta.persistence.Version;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.Instant;
import java.util.UUID;

@Entity
@Table(
        name = "channel_link_challenges",
        uniqueConstraints = @UniqueConstraint(name = "uk_channel_link_challenges_token_hash", columnNames = "token_hash"),
        indexes = {
                @Index(name = "idx_channel_link_challenges_phone", columnList = "phone_number"),
                @Index(name = "idx_channel_link_challenges_status", columnList = "status")
        }
)
@Getter
@Setter
@NoArgsConstructor
public class ChannelLinkChallenge {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    @Column(nullable = false, updatable = false)
    private UUID id;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 30)
    private ChannelLinkChannel channel = ChannelLinkChannel.WHATSAPP;

    @Column(name = "phone_number", nullable = false, length = 30)
    private String phoneNumber;

    @Column(name = "token_hash", nullable = false, length = 128)
    private String tokenHash;

    @Column(nullable = false, updatable = false)
    private Instant createdAt;

    @Column(nullable = false)
    private Instant expiresAt;

    @Column
    private Instant consumedAt;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 30)
    private ChannelLinkChallengeStatus status = ChannelLinkChallengeStatus.ACTIVE;

    @Column(length = 100)
    private String requestingClientId;

    @Version
    private long version;

    @PrePersist
    void onCreate() {
        createdAt = Instant.now();
    }
}
