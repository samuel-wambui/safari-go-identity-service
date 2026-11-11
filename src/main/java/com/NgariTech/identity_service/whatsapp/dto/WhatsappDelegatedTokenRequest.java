package com.NgariTech.identity_service.whatsapp.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record WhatsappDelegatedTokenRequest(
        @NotBlank(message = "Phone number is required")
        @Size(max = 30, message = "Phone number must be 30 characters or fewer")
        String phoneNumber,

        @Size(max = 500, message = "Scope must be 500 characters or fewer")
        String scope
) {
}
