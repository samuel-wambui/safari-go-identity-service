package com.NgariTech.identity_service.auth;

import jakarta.persistence.LockModeType;
import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;

import java.util.Optional;
import java.util.UUID;

public interface MobileGoogleLoginCodeRepository extends JpaRepository<MobileGoogleLoginCode, UUID> {

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @EntityGraph(attributePaths = "user")
    Optional<MobileGoogleLoginCode> findForUpdateByCodeHash(String codeHash);
}
