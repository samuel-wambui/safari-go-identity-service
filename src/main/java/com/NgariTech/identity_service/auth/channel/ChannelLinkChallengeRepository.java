package com.NgariTech.identity_service.auth.channel;

import jakarta.persistence.LockModeType;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.Optional;
import java.util.UUID;

public interface ChannelLinkChallengeRepository extends JpaRepository<ChannelLinkChallenge, UUID> {

    Optional<ChannelLinkChallenge> findByTokenHash(String tokenHash);

    Optional<ChannelLinkChallenge> findFirstByPhoneNumberOrderByCreatedAtDesc(String phoneNumber);

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("""
            select challenge
            from ChannelLinkChallenge challenge
            where challenge.id = :id
            """)
    Optional<ChannelLinkChallenge> findByIdForUpdate(@Param("id") UUID id);
}
