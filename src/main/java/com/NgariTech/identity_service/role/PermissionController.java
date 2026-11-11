package com.NgariTech.identity_service.role;

import com.NgariTech.identity_service.common.api.ApiResponse;
import com.NgariTech.identity_service.role.dto.PermissionRequest;
import com.NgariTech.identity_service.role.dto.PermissionResponse;
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
@RequestMapping("/api/v1/permissions")
@RequiredArgsConstructor
public class PermissionController {

    private final PermissionService permissionService;

    @PostMapping
    public ResponseEntity<ApiResponse<PermissionResponse>> create(@Valid @RequestBody PermissionRequest request) {
        PermissionResponse permission = permissionService.create(request);
        return ResponseEntity
                .created(URI.create("/api/v1/permissions/" + permission.id()))
                .body(ApiResponse.created("Permission created", permission));
    }

    @GetMapping
    public ResponseEntity<ApiResponse<List<PermissionResponse>>> findAll() {
        return ResponseEntity.ok(ApiResponse.success("Permissions retrieved", permissionService.findAll()));
    }

    @GetMapping("/{id}")
    public ResponseEntity<ApiResponse<PermissionResponse>> findById(@PathVariable String id) {
        return ResponseEntity.ok(ApiResponse.success("Permission retrieved", permissionService.findById(id)));
    }

    @PutMapping("/{id}")
    public ResponseEntity<ApiResponse<PermissionResponse>> update(
            @PathVariable String id,
            @Valid @RequestBody PermissionRequest request
    ) {
        return ResponseEntity.ok(ApiResponse.success("Permission updated", permissionService.update(id, request)));
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<ApiResponse<Void>> delete(@PathVariable String id) {
        permissionService.delete(id);
        return ResponseEntity.ok(ApiResponse.success("Permission deleted", null));
    }
}
