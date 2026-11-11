package com.NgariTech.identity_service.auth.channel;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface ChannelAuthenticationRepository extends JpaRepository<ChannelAuthentication, UUID> {

    Optional<ChannelAuthentication> findByChannelAndPhoneNumber(ChannelLinkChannel channel, String phoneNumber);

    List<ChannelAuthentication> findByChannelAndUserId(ChannelLinkChannel channel, UUID userId);
}
