package com.NgariTech.identity_service.role.dto;

import com.NgariTech.identity_service.role.Permission;

public record PermissionResponse(
        String id,
        String name,
        String description
) {

    public static PermissionResponse from(Permission permission) {
        return new PermissionResponse(
                permission.getId(),
                permission.getName(),
                permission.getDescription()
        );
    }
}
