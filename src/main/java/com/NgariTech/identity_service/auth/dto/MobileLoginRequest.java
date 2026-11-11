package com.NgariTech.identity_service.auth.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record MobileLoginRequest(
        @NotBlank(message = "phoneNumber is required")
        @Size(max = 30, message = "phoneNumber must be 30 characters or fewer")
        String phoneNumber,

        @NotBlank(message = "password is required")
        @Size(max = 72, message = "password must be 72 characters or fewer")
        String password
) {
}
