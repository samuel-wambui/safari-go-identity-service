package com.NgariTech.identity_service.auth.google;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;
import java.util.UUID;

public interface ExternalIdentityRepository extends JpaRepository<ExternalIdentity, UUID> {

    Optional<ExternalIdentity> findByProviderAndProviderSubject(
            ExternalIdentityProvider provider,
            String providerSubject
    );

    Optional<ExternalIdentity> findByUserIdAndProvider(UUID userId, ExternalIdentityProvider provider);
}
