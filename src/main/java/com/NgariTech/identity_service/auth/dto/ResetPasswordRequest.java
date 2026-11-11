package com.NgariTech.identity_service.auth.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record ResetPasswordRequest(
        @NotBlank(message = "Reset token is required")
        String token,

        @NotBlank(message = "New password is required")
        @Size(min = 8, max = 72, message = "New password must be between 8 and 72 characters")
        String password,

        @NotBlank(message = "Confirm your password")
        String confirmPassword
) {

    public static ResetPasswordRequest forToken(String token) {
        return new ResetPasswordRequest(token, "", "");
    }
}
