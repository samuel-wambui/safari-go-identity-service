package com.NgariTech.identity_service.auth.dto;

import java.time.Instant;
import java.util.UUID;

public record MobileLoginResponse(
        UUID userId,
        UUID mobileSessionId,
        String email,
        String phoneNumber,
        String firstName,
        String lastName,
        String tokenType,
        String accessToken,
        long expiresIn,
        Instant expiresAt
) {
}
