package com.NgariTech.identity_service.whatsapp.dto;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

public record WhatsappDelegatedTokenResponse(
        UUID userId,
        String phoneNumber,
        boolean authenticated,
        String actor,
        String tokenType,
        String accessToken,
        long expiresIn,
        Instant expiresAt,
        List<String> roles,
        List<String> permissions,
        List<String> scope
) {
}
