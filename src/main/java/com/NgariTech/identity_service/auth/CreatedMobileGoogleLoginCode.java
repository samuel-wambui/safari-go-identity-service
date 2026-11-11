package com.NgariTech.identity_service.auth;

import java.time.Instant;

public record CreatedMobileGoogleLoginCode(
        String code,
        String redirectUrl,
        Instant expiresAt
) {
}
