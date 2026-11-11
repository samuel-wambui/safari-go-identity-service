package com.NgariTech.identity_service.auth.dto;

import com.NgariTech.identity_service.auth.MobileSessionStatus;

import java.time.Instant;
import java.util.UUID;

public record MobileLogoutResponse(
        UUID userId,
        UUID mobileSessionId,
        MobileSessionStatus status,
        Instant revokedAt
) {
}
