package com.NgariTech.identity_service.role;

import com.NgariTech.identity_service.auth.AuditEventType;
import com.NgariTech.identity_service.auth.AuditLogService;
import com.NgariTech.identity_service.common.exception.DuplicateResourceException;
import com.NgariTech.identity_service.common.exception.ResourceNotFoundException;
import com.NgariTech.identity_service.role.dto.PermissionRequest;
import com.NgariTech.identity_service.role.dto.PermissionResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Service
@RequiredArgsConstructor
public class PermissionService {

    private final PermissionRepository permissionRepository;
    private final RoleRepository roleRepository;
    private final AuditLogService auditLogService;

    @Transactional
    public PermissionResponse create(PermissionRequest request) {
        String name = PermissionNames.normalize(request.name());
        if (permissionRepository.existsByName(name)) {
            throw new DuplicateResourceException("Permission already exists");
        }

        Permission permission = new Permission();
        permission.setId(nextPermissionId());
        permission.setName(name);
        permission.setDescription(normalizeDescription(request.description()));

        Permission savedPermission = permissionRepository.save(permission);
        auditLogService.recordSystem(AuditEventType.ROLE_CHANGE, "Permission created: " + savedPermission.getName());
        return PermissionResponse.from(savedPermission);
    }

    @Transactional(readOnly = true)
    public List<PermissionResponse> findAll() {
        return permissionRepository.findAllByOrderByNameAsc()
                .stream()
                .map(PermissionResponse::from)
                .toList();
    }

    @Transactional(readOnly = true)
    public PermissionResponse findById(String id) {
        return permissionRepository.findById(PermissionNames.normalizeId(id))
                .map(PermissionResponse::from)
                .orElseThrow(() -> new ResourceNotFoundException("Permission not found"));
    }

    @Transactional
    public PermissionResponse update(String id, PermissionRequest request) {
        Permission permission = permissionRepository.findById(PermissionNames.normalizeId(id))
                .orElseThrow(() -> new ResourceNotFoundException("Permission not found"));

        String name = PermissionNames.normalize(request.name());
        if (!permission.getName().equals(name) && permissionRepository.existsByName(name)) {
            throw new DuplicateResourceException("Permission already exists");
        }

        permission.setName(name);
        permission.setDescription(normalizeDescription(request.description()));

        Permission savedPermission = permissionRepository.save(permission);
        auditLogService.recordSystem(AuditEventType.ROLE_CHANGE, "Permission updated: " + savedPermission.getName());
        return PermissionResponse.from(savedPermission);
    }

    @Transactional
    public void delete(String id) {
        Permission permission = permissionRepository.findById(PermissionNames.normalizeId(id))
                .orElseThrow(() -> new ResourceNotFoundException("Permission not found"));

        boolean assignedToRole = roleRepository.findAll()
                .stream()
                .map(Role::getPermissionIds)
                .map(PermissionIdCodec::parse)
                .anyMatch(permissionIds -> permissionIds.contains(permission.getId()));

        if (assignedToRole) {
            throw new IllegalArgumentException("Permission cannot be deleted while assigned to roles");
        }

        permissionRepository.delete(permission);
        auditLogService.recordSystem(AuditEventType.ROLE_CHANGE, "Permission deleted: " + permission.getName());
    }

    private String nextPermissionId() {
        int nextValue = permissionRepository.findAll()
                .stream()
                .map(Permission::getId)
                .map(PermissionNames::normalizeId)
                .mapToInt(id -> Integer.parseInt(id.substring(1)))
                .max()
                .orElse(0) + 1;

        return "p%03d".formatted(nextValue);
    }

    private String normalizeDescription(String description) {
        return description == null || description.isBlank() ? null : description.trim();
    }
}
