package com.NgariTech.identity_service.auth.dto;

import jakarta.validation.constraints.AssertTrue;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.Size;

public record LogoutUserRequest(
        @Email(message = "email must be valid")
        @Size(max = 254, message = "email must be 254 characters or fewer")
        String email,

        @Size(max = 30, message = "phoneNumber must be 30 characters or fewer")
        String phoneNumber
) {

    @AssertTrue(message = "email or phoneNumber is required")
    public boolean hasIdentifier() {
        return hasText(email) || hasText(phoneNumber);
    }

    private boolean hasText(String value) {
        return value != null && !value.isBlank();
    }
}
