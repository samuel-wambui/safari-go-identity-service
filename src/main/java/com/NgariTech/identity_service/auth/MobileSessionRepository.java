package com.NgariTech.identity_service.auth;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface MobileSessionRepository extends JpaRepository<MobileSession, UUID> {

    List<MobileSession> findByUser_IdOrderByCreatedAtDesc(UUID userId);

    Optional<MobileSession> findByIdAndUser_Id(UUID id, UUID userId);
}
