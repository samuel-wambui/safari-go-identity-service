package com.NgariTech.identity_service.role.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record PermissionRequest(
        @NotBlank(message = "Permission name is required")
        @Size(max = 100, message = "Permission name must be 100 characters or fewer")
        String name,

        @Size(max = 255, message = "Description must be 255 characters or fewer")
        String description
) {
}
