package com.NgariTech.identity_service.auth.channel.dto;

import java.time.Instant;

public record CreateChannelLinkChallengeResponse(
        String registrationUrl,
        String loginUrl,
        Instant expiresAt
) {
}
