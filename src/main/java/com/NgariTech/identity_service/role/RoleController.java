package com.NgariTech.identity_service.role;

import com.NgariTech.identity_service.common.api.ApiResponse;
import com.NgariTech.identity_service.role.dto.RoleRequest;
import com.NgariTech.identity_service.role.dto.RoleResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.net.URI;
import java.util.List;

@RestController
@RequestMapping("/api/v1/roles")
@RequiredArgsConstructor
public class RoleController {

    private final RoleService roleService;

    @PostMapping
    public ResponseEntity<ApiResponse<RoleResponse>> create(@Valid @RequestBody RoleRequest request) {
        RoleResponse role = roleService.create(request);
        return ResponseEntity
                .created(URI.create("/api/v1/roles/" + role.id()))
                .body(ApiResponse.created("Role created", role));
    }

    @GetMapping
    public ResponseEntity<ApiResponse<List<RoleResponse>>> findAll() {
        return ResponseEntity.ok(ApiResponse.success("Roles retrieved", roleService.findAll()));
    }

    @GetMapping("/{id}")
    public ResponseEntity<ApiResponse<RoleResponse>> findById(@PathVariable String id) {
        return ResponseEntity.ok(ApiResponse.success("Role retrieved", roleService.findById(id)));
    }

    @PutMapping("/{id}")
    public ResponseEntity<ApiResponse<RoleResponse>> update(
            @PathVariable String id,
            @Valid @RequestBody RoleRequest request
    ) {
        return ResponseEntity.ok(ApiResponse.success("Role updated", roleService.update(id, request)));
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<ApiResponse<Void>> delete(@PathVariable String id) {
        roleService.delete(id);
        return ResponseEntity.ok(ApiResponse.success("Role deleted", null));
    }

    @PostMapping("/{roleId}/permissions/{permissionId}")
    public ResponseEntity<ApiResponse<RoleResponse>> assignPermission(
            @PathVariable String roleId,
            @PathVariable String permissionId
    ) {
        return ResponseEntity.ok(ApiResponse.success(
                "Permission assigned to role",
                roleService.assignPermission(roleId, permissionId)
        ));
    }

    @DeleteMapping("/{roleId}/permissions/{permissionId}")
    public ResponseEntity<ApiResponse<RoleResponse>> removePermission(
            @PathVariable String roleId,
            @PathVariable String permissionId
    ) {
        return ResponseEntity.ok(ApiResponse.success(
                "Permission removed from role",
                roleService.removePermission(roleId, permissionId)
        ));
    }
}
