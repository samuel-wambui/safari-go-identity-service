package com.NgariTech.identity_service.auth.channel.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record CreateChannelLinkChallengeRequest(
        @NotBlank(message = "Phone number is required")
        @Size(max = 30, message = "Phone number must be 30 characters or fewer")
        String phoneNumber,

        @Size(max = 100, message = "Requesting client id must be 100 characters or fewer")
        String requestingClientId,

        @Size(max = 500, message = "Login URL must be 500 characters or fewer")
        String loginUrl
) {
        public CreateChannelLinkChallengeRequest(String phoneNumber, String requestingClientId) {
                this(phoneNumber, requestingClientId, null);
        }
}
