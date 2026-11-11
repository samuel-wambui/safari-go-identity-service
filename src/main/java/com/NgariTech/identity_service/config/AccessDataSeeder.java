package com.NgariTech.identity_service.config;

import com.NgariTech.identity_service.role.Permission;
import com.NgariTech.identity_service.role.PermissionIdCodec;
import com.NgariTech.identity_service.role.PermissionNames;
import com.NgariTech.identity_service.role.PermissionRepository;
import com.NgariTech.identity_service.role.Role;
import com.NgariTech.identity_service.role.RoleNames;
import com.NgariTech.identity_service.role.RoleRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.util.Set;

@Component
@RequiredArgsConstructor
public class AccessDataSeeder implements ApplicationRunner {

    private final RoleRepository roleRepository;
    private final PermissionRepository permissionRepository;

    @Override
    @Transactional
    public void run(ApplicationArguments args) {
        seedPermissions();
        seedRoles();
        assignDefaultPermissions();
    }

    private void seedPermissions() {
        PermissionNames.DEFAULT_PERMISSIONS.forEach(defaultPermission -> {
            if (!permissionRepository.existsById(defaultPermission.id())) {
                Permission permission = new Permission();
                permission.setId(defaultPermission.id());
                permission.setName(defaultPermission.name());
                permission.setDescription(defaultPermission.description());
                permissionRepository.save(permission);
            }
        });
    }

    private void seedRoles() {
        RoleNames.DEFAULT_ROLES.forEach(defaultRole -> {
            if (!roleRepository.existsById(defaultRole.id())) {
                Role role = new Role();
                role.setId(defaultRole.id());
                role.setName(defaultRole.name());
                role.setDescription(defaultRole.description());
                roleRepository.save(role);
            }
        });
    }

    private void assignDefaultPermissions() {
        assignPermissions(RoleNames.ADMIN_ID, Set.of(
                PermissionNames.MENU_READ_ID,
                PermissionNames.MENU_CREATE_ID,
                PermissionNames.MENU_UPDATE_ID,
                PermissionNames.MENU_DELETE_ID
        ));

        assignPermissions(RoleNames.USER_ID, Set.of(
                PermissionNames.TRAVEL_READ_ID,
                PermissionNames.TRAVEL_CREATE_ID,
                PermissionNames.PAYMENT_CREATE_ID,
                PermissionNames.PAYMENT_READ_ID
        ));

        assignPermissions(RoleNames.TRAVELLER_ID, Set.of(
                PermissionNames.TRAVEL_READ_ID,
                PermissionNames.TRAVEL_CREATE_ID,
                PermissionNames.PAYMENT_CREATE_ID,
                PermissionNames.PAYMENT_READ_ID
        ));

        assignPermissions(RoleNames.SUPER_ADMIN_ID, PermissionNames.DEFAULT_PERMISSIONS.stream()
                .map(PermissionNames.DefaultPermission::id)
                .collect(java.util.stream.Collectors.toSet()));
    }

    private void assignPermissions(String roleId, Set<String> permissionIds) {
        Role role = roleRepository.findById(roleId)
                .orElseThrow(() -> new IllegalStateException("Seeded role missing: " + roleId));

        role.setPermissionIds(PermissionIdCodec.format(permissionIds));
        roleRepository.save(role);
    }
}
