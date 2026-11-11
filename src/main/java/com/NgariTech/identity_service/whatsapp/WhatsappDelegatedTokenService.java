package com.NgariTech.identity_service.whatsapp;

import com.NgariTech.identity_service.auth.AuditEventType;
import com.NgariTech.identity_service.auth.AuditLogService;
import com.NgariTech.identity_service.auth.oidc.IamTokenClaimService;
import com.NgariTech.identity_service.user.PhoneNumberNormalizer;
import com.NgariTech.identity_service.user.UserAccount;
import com.NgariTech.identity_service.user.UserRepository;
import com.NgariTech.identity_service.whatsapp.dto.WhatsappAuthStatusResponse;
import com.NgariTech.identity_service.whatsapp.dto.WhatsappDelegatedTokenRequest;
import com.NgariTech.identity_service.whatsapp.dto.WhatsappDelegatedTokenResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import jakarta.servlet.http.HttpServletRequest;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class WhatsappDelegatedTokenService {

    private final WhatsappIdentityService whatsappIdentityService;
    private final UserRepository userRepository;
    private final IamTokenClaimService tokenClaimService;
    private final AuditLogService auditLogService;
    private final JwtEncoder jwtEncoder;

    @Value("${security.jwt.issuer}")
    private String issuer;

    @Value("${security.jwt.audience}")
    private String audience;

    @Value("${security.jwt.key-id}")
    private String keyId;

    @Value("${iam.oauth2.token.delegated-token-minutes:5}")
    private long delegatedTokenMinutes;

    @Transactional(readOnly = true)
    public WhatsappDelegatedTokenResponse issueDelegatedToken(
            WhatsappDelegatedTokenRequest request,
            Authentication authentication,
            HttpServletRequest servletRequest
    ) {
        String actor = actor(authentication);
        String normalizedPhoneNumber = PhoneNumberNormalizer.normalize(request.phoneNumber());
        WhatsappAuthStatusResponse status = whatsappIdentityService.authenticationStatus(normalizedPhoneNumber);

        if (!status.registered() || !status.authenticated() || status.userId() == null) {
            auditFailure(normalizedPhoneNumber, actor, servletRequest, "Delegated token denied because WhatsApp user is not authenticated");
            throw new AccessDeniedException("WhatsApp account is not authenticated");
        }

        UserAccount account = userRepository.findByIdAndDeletedFalse(status.userId())
                .orElseThrow(() -> {
                    auditFailure(normalizedPhoneNumber, actor, servletRequest, "Delegated token denied because user account is unavailable");
                    return new AccessDeniedException("WhatsApp account is not authenticated");
                });

        if (!account.isEnabled() || !account.isAccountNonLocked()) {
            auditFailure(normalizedPhoneNumber, actor, servletRequest, "Delegated token denied because user account is unavailable");
            throw new AccessDeniedException("WhatsApp account is not authenticated");
        }

        List<String> roles = tokenClaimService.roleNames(account);
        List<String> userPermissions = tokenClaimService.permissionNames(account);
        List<String> grantedScopes = grantedScopes(request.scope(), userPermissions);
        Instant issuedAt = Instant.now();
        Instant expiresAt = issuedAt.plus(Duration.ofMinutes(delegatedTokenMinutes));

        JwtClaimsSet claims = JwtClaimsSet.builder()
                .issuer(issuer)
                .subject(account.getId().toString())
                .audience(List.of(audience))
                .issuedAt(issuedAt)
                .expiresAt(expiresAt)
                .id(UUID.randomUUID().toString())
                .claim("user_id", account.getId().toString())
                .claim("email", account.getEmail())
                .claim("email_verified", account.isEmailVerified())
                .claim("roles", roles)
                .claim("permissions", grantedScopes)
                .claim("scope", grantedScopes)
                .claim("client_id", actor)
                .claim("delegated", true)
                .claim("auth_method", "WHATSAPP")
                .claim("act", Map.of("sub", actor, "client_id", actor))
                .build();

        JwsHeader header = JwsHeader.with(SignatureAlgorithm.RS256)
                .keyId(keyId)
                .build();
        String token = jwtEncoder.encode(JwtEncoderParameters.from(header, claims)).getTokenValue();

        auditLogService.record(
                AuditEventType.TOKEN_ISSUED,
                account.getId(),
                account.getEmail(),
                sourceIp(servletRequest),
                servletRequest.getHeader("User-Agent"),
                "Delegated WhatsApp access token issued for actor " + actor
        );

        return new WhatsappDelegatedTokenResponse(
                account.getId(),
                normalizedPhoneNumber,
                true,
                actor,
                "Bearer",
                token,
                Duration.between(issuedAt, expiresAt).toSeconds(),
                expiresAt,
                roles,
                grantedScopes,
                grantedScopes
        );
    }

    private String actor(Authentication authentication) {
        if (authentication == null || authentication.getName() == null || authentication.getName().isBlank()) {
            throw new AccessDeniedException("Service authentication is required");
        }

        boolean n8nService = authentication.getAuthorities()
                .stream()
                .anyMatch(authority -> "service:n8n".equals(authority.getAuthority()));
        if (!n8nService) {
            throw new AccessDeniedException("Service authentication is required");
        }

        return authentication.getName();
    }

    private List<String> grantedScopes(String requestedScope, List<String> userPermissions) {
        Set<String> allowed = new LinkedHashSet<>(userPermissions);
        List<String> requested = parseScope(requestedScope);

        if (requested.isEmpty()) {
            return List.copyOf(allowed);
        }

        List<String> denied = requested.stream()
                .filter(scope -> !allowed.contains(scope))
                .toList();
        if (!denied.isEmpty()) {
            throw new AccessDeniedException("Requested scope is not allowed");
        }

        return requested;
    }

    private List<String> parseScope(String scope) {
        if (scope == null || scope.isBlank()) {
            return List.of();
        }

        return Arrays.stream(scope.trim().split("[\\s,]+"))
                .map(String::trim)
                .filter(value -> !value.isBlank())
                .distinct()
                .toList();
    }

    private void auditFailure(String phoneNumber, String actor, HttpServletRequest servletRequest, String details) {
        auditLogService.record(
                AuditEventType.TOKEN_FAILURE,
                null,
                null,
                sourceIp(servletRequest),
                servletRequest.getHeader("User-Agent"),
                details + " (" + actor + ")"
        );
    }

    private String sourceIp(HttpServletRequest request) {
        String forwardedFor = request.getHeader("X-Forwarded-For");
        if (forwardedFor != null && !forwardedFor.isBlank()) {
            return forwardedFor.split(",")[0].trim();
        }

        return request.getRemoteAddr();
    }
}
