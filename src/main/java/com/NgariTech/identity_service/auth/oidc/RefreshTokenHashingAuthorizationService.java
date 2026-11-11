package com.NgariTech.identity_service.auth.oidc;

import com.NgariTech.identity_service.auth.AuditEventType;
import com.NgariTech.identity_service.auth.AuditLogService;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.UUID;

@RequiredArgsConstructor
public class RefreshTokenHashingAuthorizationService implements OAuth2AuthorizationService {

    private static final String HASH_PREFIX = "sha256:";

    private final JdbcOAuth2AuthorizationService delegate;
    private final JdbcTemplate jdbcTemplate;
    private final AuditLogService auditLogService;

    public RefreshTokenHashingAuthorizationService(
            JdbcTemplate jdbcTemplate,
            RegisteredClientRepository registeredClientRepository,
            AuditLogService auditLogService
    ) {
        this(new JdbcOAuth2AuthorizationService(jdbcTemplate, registeredClientRepository), jdbcTemplate, auditLogService);
    }

    @Override
    @Transactional
    public void save(OAuth2Authorization authorization) {
        delegate.save(withHashedRefreshToken(authorization));
        trackRefreshToken(authorization);
    }

    @Override
    @Transactional
    public void remove(OAuth2Authorization authorization) {
        delegate.remove(withHashedRefreshToken(authorization));
        markAuthorizationRevoked(authorization.getId());
    }

    @Override
    @Transactional(readOnly = true)
    public OAuth2Authorization findById(String id) {
        return delegate.findById(id);
    }

    @Override
    @Transactional
    public OAuth2Authorization findByToken(String token, OAuth2TokenType tokenType) {
        if (token == null || token.isBlank()) {
            return null;
        }

        if (OAuth2TokenType.REFRESH_TOKEN.equals(tokenType)) {
            return findByRefreshToken(token);
        }

        OAuth2Authorization authorization = delegate.findByToken(token, tokenType);
        if (authorization != null || tokenType != null) {
            return authorization;
        }

        return findByRefreshToken(token);
    }

    private OAuth2Authorization findByRefreshToken(String rawToken) {
        OAuth2Authorization authorization = delegate.findByToken(hash(rawToken), OAuth2TokenType.REFRESH_TOKEN);
        if (authorization != null) {
            return withRefreshTokenValue(authorization, rawToken);
        }

        detectRefreshTokenReuse(rawToken);
        return null;
    }

    private OAuth2Authorization withHashedRefreshToken(OAuth2Authorization authorization) {
        OAuth2Authorization.Token<OAuth2RefreshToken> refreshToken = authorization.getRefreshToken();
        if (refreshToken == null) {
            return authorization;
        }

        String tokenValue = refreshToken.getToken().getTokenValue();
        if (isHash(tokenValue)) {
            return authorization;
        }

        return withRefreshTokenValue(authorization, hash(tokenValue));
    }

    private OAuth2Authorization withRefreshTokenValue(OAuth2Authorization authorization, String tokenValue) {
        OAuth2Authorization.Token<OAuth2RefreshToken> refreshToken = authorization.getRefreshToken();
        if (refreshToken == null) {
            return authorization;
        }

        OAuth2RefreshToken token = refreshToken.getToken();
        OAuth2RefreshToken replacement = new OAuth2RefreshToken(
                tokenValue,
                token.getIssuedAt(),
                token.getExpiresAt()
        );

        return OAuth2Authorization.from(authorization)
                .token(replacement, metadata -> {
                    metadata.clear();
                    metadata.putAll(refreshToken.getMetadata());
                })
                .build();
    }

    private void trackRefreshToken(OAuth2Authorization authorization) {
        OAuth2Authorization.Token<OAuth2RefreshToken> refreshToken = authorization.getRefreshToken();
        if (refreshToken == null) {
            return;
        }

        String tokenHash = tokenHash(refreshToken.getToken().getTokenValue());
        if (refreshToken.isInvalidated()) {
            markTokenRevoked(tokenHash);
            return;
        }

        if (!refreshToken.isActive()) {
            return;
        }

        boolean alreadyRecorded = Boolean.TRUE.equals(jdbcTemplate.query(
                "select exists(select 1 from oauth2_refresh_tokens where token_hash = ?)",
                ps -> ps.setString(1, tokenHash),
                rs -> rs.next() && rs.getBoolean(1)
        ));

        if (alreadyRecorded) {
            return;
        }

        UUID familyId = tokenFamilyId(authorization.getId());
        Instant now = Instant.now();
        jdbcTemplate.update("""
                update oauth2_refresh_tokens
                set used_at = coalesce(used_at, ?)
                where authorization_id = ?
                  and revoked_at is null
                  and used_at is null
                """,
                Timestamp.from(now),
                authorization.getId()
        );

        HttpServletRequest request = currentRequest();
        jdbcTemplate.update("""
                insert into oauth2_refresh_tokens (
                    id,
                    authorization_id,
                    registered_client_id,
                    principal_name,
                    token_family_id,
                    token_hash,
                    issued_at,
                    expires_at,
                    source_ip,
                    user_agent,
                    created_at
                )
                values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                UUID.randomUUID(),
                authorization.getId(),
                authorization.getRegisteredClientId(),
                authorization.getPrincipalName(),
                familyId,
                tokenHash,
                timestamp(refreshToken.getToken().getIssuedAt()),
                timestamp(refreshToken.getToken().getExpiresAt()),
                sourceIp(request),
                userAgent(request),
                Timestamp.from(now)
        );
    }

    private UUID tokenFamilyId(String authorizationId) {
        List<UUID> familyIds = jdbcTemplate.query(
                """
                select token_family_id
                from oauth2_refresh_tokens
                where authorization_id = ?
                order by created_at asc
                limit 1
                """,
                (rs, rowNum) -> rs.getObject("token_family_id", UUID.class),
                authorizationId
        );

        if (familyIds.isEmpty()) {
            return UUID.randomUUID();
        }

        return familyIds.get(0);
    }

    private void detectRefreshTokenReuse(String rawToken) {
        String tokenHash = hash(rawToken);
        List<RefreshTokenRecord> records = jdbcTemplate.query(
                """
                select token_family_id, principal_name, registered_client_id
                from oauth2_refresh_tokens
                where token_hash = ?
                  and used_at is not null
                  and revoked_at is null
                """,
                (rs, rowNum) -> new RefreshTokenRecord(
                        rs.getObject("token_family_id", UUID.class),
                        rs.getString("principal_name"),
                        rs.getString("registered_client_id")
                ),
                tokenHash
        );

        if (records.isEmpty()) {
            return;
        }

        RefreshTokenRecord record = records.get(0);
        Instant now = Instant.now();
        jdbcTemplate.update(
                """
                update oauth2_refresh_tokens
                set reused_at = coalesce(reused_at, ?),
                    revoked_at = coalesce(revoked_at, ?)
                where token_family_id = ?
                """,
                Timestamp.from(now),
                Timestamp.from(now),
                record.familyId()
        );

        jdbcTemplate.update(
                """
                delete from oauth2_authorization
                where id in (
                    select authorization_id
                    from oauth2_refresh_tokens
                    where token_family_id = ?
                )
                """,
                record.familyId()
        );

        auditLogService.record(
                AuditEventType.REFRESH_REUSE_DETECTED,
                parseUuid(record.principalName()),
                null,
                sourceIp(currentRequest()),
                userAgent(currentRequest()),
                "Refresh token reuse detected for client " + record.registeredClientId()
        );
    }

    private void markAuthorizationRevoked(String authorizationId) {
        jdbcTemplate.update(
                """
                update oauth2_refresh_tokens
                set revoked_at = coalesce(revoked_at, ?)
                where authorization_id = ?
                """,
                Timestamp.from(Instant.now()),
                authorizationId
        );
    }

    private void markTokenRevoked(String tokenHash) {
        jdbcTemplate.update(
                """
                update oauth2_refresh_tokens
                set revoked_at = coalesce(revoked_at, ?)
                where token_hash = ?
                """,
                Timestamp.from(Instant.now()),
                tokenHash
        );
    }

    private String tokenHash(String tokenValue) {
        return isHash(tokenValue) ? tokenValue : hash(tokenValue);
    }

    private boolean isHash(String tokenValue) {
        return tokenValue != null && tokenValue.startsWith(HASH_PREFIX);
    }

    private String hash(String tokenValue) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(tokenValue.getBytes(StandardCharsets.UTF_8));
            return HASH_PREFIX + Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
        }
        catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException("SHA-256 digest is unavailable", exception);
        }
    }

    private Timestamp timestamp(Instant instant) {
        return instant == null ? null : Timestamp.from(instant);
    }

    private UUID parseUuid(String principalName) {
        try {
            return UUID.fromString(principalName);
        }
        catch (IllegalArgumentException exception) {
            return null;
        }
    }

    private HttpServletRequest currentRequest() {
        if (RequestContextHolder.getRequestAttributes() instanceof ServletRequestAttributes attributes) {
            return attributes.getRequest();
        }

        return null;
    }

    private String sourceIp(HttpServletRequest request) {
        if (request == null) {
            return null;
        }

        String forwardedFor = request.getHeader("X-Forwarded-For");
        if (forwardedFor != null && !forwardedFor.isBlank()) {
            return forwardedFor.split(",")[0].trim();
        }

        return request.getRemoteAddr();
    }

    private String userAgent(HttpServletRequest request) {
        return request == null ? null : request.getHeader("User-Agent");
    }

    private record RefreshTokenRecord(UUID familyId, String principalName, String registeredClientId) {
    }
}
