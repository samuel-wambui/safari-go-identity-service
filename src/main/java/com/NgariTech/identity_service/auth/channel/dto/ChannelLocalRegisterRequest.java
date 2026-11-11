package com.NgariTech.identity_service.auth.channel.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record ChannelLocalRegisterRequest(
        @NotBlank(message = "First name is required")
        @Size(max = 100, message = "First name must be 100 characters or fewer")
        String firstName,

        @NotBlank(message = "Last name is required")
        @Size(max = 100, message = "Last name must be 100 characters or fewer")
        String lastName,

        @NotBlank(message = "Email is required")
        @Email(message = "Email must be valid")
        @Size(max = 254, message = "Email must be 254 characters or fewer")
        String email,

        @NotBlank(message = "Password is required")
        @Size(min = 8, max = 72, message = "Password must be between 8 and 72 characters")
        String password,

        @NotBlank(message = "Confirm your password")
        @Size(min = 8, max = 72, message = "Password must be between 8 and 72 characters")
        String confirmPassword
) {

    public static ChannelLocalRegisterRequest empty() {
        return new ChannelLocalRegisterRequest("", "", "", "", "");
    }
}
