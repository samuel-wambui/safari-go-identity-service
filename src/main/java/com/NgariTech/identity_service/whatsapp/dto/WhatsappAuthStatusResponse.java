package com.NgariTech.identity_service.whatsapp.dto;

import com.NgariTech.identity_service.whatsapp.WhatsappAuthStatus;

import java.util.UUID;

public record WhatsappAuthStatusResponse(
        String phoneNumber,
        boolean registered,
        boolean authenticated,
        UUID userId,
        WhatsappAuthStatus status
) {
}
