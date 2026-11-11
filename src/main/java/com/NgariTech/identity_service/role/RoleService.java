package com.NgariTech.identity_service.role;

import com.NgariTech.identity_service.auth.AuditEventType;
import com.NgariTech.identity_service.auth.AuditLogService;
import com.NgariTech.identity_service.common.exception.DuplicateResourceException;
import com.NgariTech.identity_service.common.exception.ResourceNotFoundException;
import com.NgariTech.identity_service.role.dto.RoleRequest;
import com.NgariTech.identity_service.role.dto.RoleResponse;
import com.NgariTech.identity_service.user.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Collection;
import java.util.Comparator;
import java.util.List;
import java.util.Set;

@Service
@RequiredArgsConstructor
public class RoleService {

    private final RoleRepository roleRepository;
    private final PermissionRepository permissionRepository;
    private final UserRepository userRepository;
    private final AuditLogService auditLogService;

    @Transactional
    public RoleResponse create(RoleRequest request) {
        String name = RoleNames.normalize(request.name());
        if (roleRepository.existsByName(name)) {
            throw new DuplicateResourceException("Role already exists");
        }

        Role role = new Role();
        role.setId(nextRoleId());
        role.setName(name);
        role.setDescription(normalizeDescription(request.description()));

        Role savedRole = roleRepository.save(role);
        auditLogService.recordSystem(AuditEventType.ROLE_CHANGE, "Role created: " + savedRole.getName());
        return toResponse(savedRole);
    }

    @Transactional(readOnly = true)
    public List<RoleResponse> findAll() {
        return roleRepository.findAllByOrderByNameAsc()
                .stream()
                .map(this::toResponse)
                .toList();
    }

    @Transactional(readOnly = true)
    public RoleResponse findById(String id) {
        return roleRepository.findById(RoleNames.normalizeId(id))
                .map(this::toResponse)
                .orElseThrow(() -> new ResourceNotFoundException("Role not found"));
    }

    @Transactional
    public RoleResponse update(String id, RoleRequest request) {
        Role role = roleRepository.findById(RoleNames.normalizeId(id))
                .orElseThrow(() -> new ResourceNotFoundException("Role not found"));

        String name = RoleNames.normalize(request.name());
        if (RoleNames.USER.equals(role.getName()) && !RoleNames.USER.equals(name)) {
            throw new IllegalArgumentException("Default USER role cannot be renamed");
        }

        if (!role.getName().equals(name) && roleRepository.existsByName(name)) {
            throw new DuplicateResourceException("Role already exists");
        }

        role.setName(name);
        role.setDescription(normalizeDescription(request.description()));

        Role savedRole = roleRepository.save(role);
        auditLogService.recordSystem(AuditEventType.ROLE_CHANGE, "Role updated: " + savedRole.getName());
        return toResponse(savedRole);
    }

    @Transactional
    public void delete(String id) {
        Role role = roleRepository.findById(RoleNames.normalizeId(id))
                .orElseThrow(() -> new ResourceNotFoundException("Role not found"));

        if (RoleNames.USER.equals(role.getName())) {
            throw new IllegalArgumentException("Default USER  role cannot be deleted");
        }

        if (userRepository.countByRoleId(role.getId()) > 0) {
            throw new IllegalArgumentException("Role cannot be deleted while assigned to users");
        }

        roleRepository.delete(role);
        auditLogService.recordSystem(AuditEventType.ROLE_CHANGE, "Role deleted: " + role.getName());
    }

    @Transactional
    public RoleResponse assignPermission(String roleId, String permissionId) {
        Role role = roleRepository.findById(RoleNames.normalizeId(roleId))
                .orElseThrow(() -> new ResourceNotFoundException("Role not found"));
        Permission permission = permissionRepository.findById(PermissionNames.normalizeId(permissionId))
                .orElseThrow(() -> new ResourceNotFoundException("Permission not found"));

        Set<String> permissionIds = PermissionIdCodec.parse(role.getPermissionIds());
        permissionIds.add(permission.getId());
        role.setPermissionIds(PermissionIdCodec.format(permissionIds));

        Role savedRole = roleRepository.save(role);
        auditLogService.recordSystem(
                AuditEventType.ROLE_CHANGE,
                "Permission " + permission.getName() + " assigned to role " + savedRole.getName()
        );
        return toResponse(savedRole);
    }

    @Transactional
    public RoleResponse removePermission(String roleId, String permissionId) {
        Role role = roleRepository.findById(RoleNames.normalizeId(roleId))
                .orElseThrow(() -> new ResourceNotFoundException("Role not found"));

        Set<String> permissionIds = PermissionIdCodec.parse(role.getPermissionIds());
        String normalizedPermissionId = PermissionNames.normalizeId(permissionId);
        permissionIds.remove(normalizedPermissionId);
        role.setPermissionIds(PermissionIdCodec.format(permissionIds));

        Role savedRole = roleRepository.save(role);
        auditLogService.recordSystem(
                AuditEventType.ROLE_CHANGE,
                "Permission " + normalizedPermissionId + " removed from role " + savedRole.getName()
        );
        return toResponse(savedRole);
    }

    private RoleResponse toResponse(Role role) {
        List<String> permissionNames = findPermissions(PermissionIdCodec.parse(role.getPermissionIds()))
                .stream()
                .map(Permission::getName)
                .sorted(Comparator.naturalOrder())
                .toList();

        return RoleResponse.from(role, permissionNames);
    }

    private List<Permission> findPermissions(Collection<String> permissionIds) {
        if (permissionIds == null || permissionIds.isEmpty()) {
            return List.of();
        }

        return permissionRepository.findByIdInOrderByNameAsc(permissionIds);
    }

    private String nextRoleId() {
        int nextValue = roleRepository.findAll()
                .stream()
                .map(Role::getId)
                .map(RoleNames::normalizeId)
                .mapToInt(id -> Integer.parseInt(id.substring(1)))
                .max()
                .orElse(0) + 1;

        return "r%03d".formatted(nextValue);
    }

    private String normalizeDescription(String description) {
        return description == null || description.isBlank() ? null : description.trim();
    }
}
