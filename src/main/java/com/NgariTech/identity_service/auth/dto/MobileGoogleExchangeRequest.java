package com.NgariTech.identity_service.auth.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record MobileGoogleExchangeRequest(
        @NotBlank(message = "code is required")
        @Size(max = 256, message = "code must be 256 characters or fewer")
        String code
) {
}
