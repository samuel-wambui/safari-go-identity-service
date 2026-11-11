package com.NgariTech.identity_service.auth.dto;

import java.util.UUID;

public record LogoutUserResponse(
        UUID userId,
        String email,
        String phoneNumber,
        int activeAuthorizations,
        int activeRefreshTokens,
        int revokedAuthorizations,
        int revokedRefreshTokens,
        int revokedChannelAuthentications
) {
}
