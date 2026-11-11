package com.NgariTech.identity_service.role.dto;

import com.NgariTech.identity_service.role.PermissionIdCodec;
import com.NgariTech.identity_service.role.Role;

import java.util.List;

public record RoleResponse(
        String id,
        String name,
        String description,
        List<String> permissionIds,
        List<String> permissions
) {

    public static RoleResponse from(Role role, List<String> permissions) {
        return new RoleResponse(
                role.getId(),
                role.getName(),
                role.getDescription(),
                PermissionIdCodec.parse(role.getPermissionIds()).stream().toList(),
                permissions
        );
    }
}
