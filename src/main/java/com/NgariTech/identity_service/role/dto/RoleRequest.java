package com.NgariTech.identity_service.role.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record RoleRequest(
        @NotBlank(message = "Role name is required")
        @Size(max = 50, message = "Role name must be 50 characters or fewer")
        String name,

        @Size(max = 255, message = "Description must be 255 characters or fewer")
        String description
) {
}
