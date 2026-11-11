package com.NgariTech.identity_service.security;

import com.NgariTech.identity_service.role.Permission;
import com.NgariTech.identity_service.role.PermissionIdCodec;
import com.NgariTech.identity_service.role.PermissionRepository;
import com.NgariTech.identity_service.role.Role;
import com.NgariTech.identity_service.role.RoleRepository;
import com.NgariTech.identity_service.user.UserAccount;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Set;

@Service
@RequiredArgsConstructor
public class IamUserPrincipalService {

    private final RoleRepository roleRepository;
    private final PermissionRepository permissionRepository;

    @Transactional(readOnly = true)
    public UserDetails userDetails(UserAccount account) {
        Role role = roleRepository.findById(account.getRoleId())
                .orElseThrow(() -> new UsernameNotFoundException("Invalid credentials"));

        List<String> permissions = permissionNames(role);

        return User.builder()
                .username(account.getId().toString())
                .password(account.getPassword())
                .authorities(authorities(role, permissions))
                .disabled(!account.isEnabled())
                .accountLocked(!account.isAccountNonLocked())
                .build();
    }

    private String[] authorities(Role role, List<String> permissions) {
        return java.util.stream.Stream.concat(
                        java.util.stream.Stream.of("ROLE_" + role.getName()),
                        permissions.stream()
                )
                .toArray(String[]::new);
    }

    private List<String> permissionNames(Role role) {
        Set<String> permissionIds = PermissionIdCodec.parse(role.getPermissionIds());
        if (permissionIds.isEmpty()) {
            return List.of();
        }

        return permissionRepository.findByIdInOrderByNameAsc(permissionIds)
                .stream()
                .map(Permission::getName)
                .sorted()
                .toList();
    }
}
