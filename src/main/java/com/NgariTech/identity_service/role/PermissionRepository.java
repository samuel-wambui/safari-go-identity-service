package com.NgariTech.identity_service.role;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Collection;
import java.util.List;
import java.util.Optional;

public interface PermissionRepository extends JpaRepository<Permission, String> {

    boolean existsByName(String name);

    Optional<Permission> findByName(String name);

    List<Permission> findAllByOrderByNameAsc();

    List<Permission> findByIdInOrderByNameAsc(Collection<String> ids);
}
