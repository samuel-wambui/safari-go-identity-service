package com.NgariTech.identity_service.auth.oidc;

import com.NgariTech.identity_service.user.UserAccount;
import lombok.RequiredArgsConstructor;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.sql.Timestamp;
import java.time.Instant;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class AuthorizationRevocationService {

    private final JdbcTemplate jdbcTemplate;

    @Transactional
    public RevocationResult revokeAllForUser(UserAccount account) {
        return revokeAllForUser(account.getId(), account.getEmail());
    }

    @Transactional
    public RevocationResult revokeAllForUser(UUID userId, String email) {
        int activeRefreshTokens = jdbcTemplate.queryForObject(
                """
                select count(*)
                from oauth2_refresh_tokens
                where (principal_name = ? or principal_name = ?)
                  and used_at is null
                  and revoked_at is null
                  and reused_at is null
                  and (expires_at is null or expires_at > ?)
                """,
                Integer.class,
                userId.toString(),
                email,
                Timestamp.from(Instant.now())
        );

        int activeAuthorizations = jdbcTemplate.queryForObject(
                """
                select count(*)
                from oauth2_authorization
                where principal_name = ? or principal_name = ?
                """,
                Integer.class,
                userId.toString(),
                email
        );

        int revokedRefreshTokens = jdbcTemplate.update(
                """
                update oauth2_refresh_tokens
                set revoked_at = coalesce(revoked_at, current_timestamp)
                where principal_name = ? or principal_name = ?
                  and revoked_at is null
                """,
                userId.toString(),
                email
        );

        int revokedAuthorizations = jdbcTemplate.update(
                "delete from oauth2_authorization where principal_name = ? or principal_name = ?",
                userId.toString(),
                email
        );

        return new RevocationResult(
                activeAuthorizations,
                activeRefreshTokens,
                revokedAuthorizations,
                revokedRefreshTokens
        );
    }

    public record RevocationResult(
            int activeAuthorizations,
            int activeRefreshTokens,
            int revokedAuthorizations,
            int revokedRefreshTokens
    ) {
    }
}
