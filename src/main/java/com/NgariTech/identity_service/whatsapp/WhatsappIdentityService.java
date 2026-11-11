package com.NgariTech.identity_service.whatsapp;

import com.NgariTech.identity_service.auth.LoginAttemptService;
import com.NgariTech.identity_service.auth.channel.ChannelAuthenticationService;
import com.NgariTech.identity_service.user.PhoneNumberNormalizer;
import com.NgariTech.identity_service.user.UserAccount;
import com.NgariTech.identity_service.user.UserRepository;
import com.NgariTech.identity_service.whatsapp.dto.WhatsappAuthStatusResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.sql.Timestamp;
import java.time.Instant;

@Service
@RequiredArgsConstructor
public class WhatsappIdentityService {

    private final UserRepository userRepository;
    private final JdbcTemplate jdbcTemplate;
    private final LoginAttemptService loginAttemptService;
    private final ChannelAuthenticationService channelAuthenticationService;

    @Transactional(readOnly = true)
    public WhatsappAuthStatusResponse authenticationStatus(String phoneNumber) {
        String normalizedPhoneNumber = PhoneNumberNormalizer.normalize(phoneNumber);

        return userRepository.findByPhoneNumberAndDeletedFalse(normalizedPhoneNumber)
                .or(() -> userRepository.findByNormalizedPhoneNumberAndDeletedFalse(normalizedPhoneNumber))
                .map(account -> statusForAccount(refreshExpiredLock(account), normalizedPhoneNumber))
                .orElseGet(() -> new WhatsappAuthStatusResponse(
                        normalizedPhoneNumber,
                        false,
                        false,
                        null,
                        WhatsappAuthStatus.NOT_REGISTERED
                ));
    }

    private UserAccount refreshExpiredLock(UserAccount account) {
        Instant lockExpiresAt = account.getLockExpiresAt();
        if (account.isAccountNonLocked() || lockExpiresAt == null || Instant.now().isBefore(lockExpiresAt)) {
            return account;
        }

        loginAttemptService.unlockIfExpired(account.getEmail(), null, null);
        return userRepository.findByIdAndDeletedFalse(account.getId()).orElse(account);
    }

    private WhatsappAuthStatusResponse statusForAccount(UserAccount account, String phoneNumber) {
        if (!account.isEnabled() || !account.isAccountNonLocked()) {
            return new WhatsappAuthStatusResponse(
                    phoneNumber,
                    true,
                    false,
                    account.getId(),
                    WhatsappAuthStatus.ACCOUNT_UNAVAILABLE
            );
        }

        boolean authenticated = hasActiveRefreshToken(account)
                || channelAuthenticationService.hasActiveWhatsappAuthentication(account, phoneNumber);
        return new WhatsappAuthStatusResponse(
                phoneNumber,
                true,
                authenticated,
                account.getId(),
                authenticated
                        ? WhatsappAuthStatus.AUTHENTICATED
                        : WhatsappAuthStatus.AUTHENTICATION_REQUIRED
        );
    }

    private boolean hasActiveRefreshToken(UserAccount account) {
        Long activeTokens = jdbcTemplate.queryForObject(
                """
                select count(*)
                from oauth2_refresh_tokens
                where principal_name = ?
                  and used_at is null
                  and revoked_at is null
                  and reused_at is null
                  and (expires_at is null or expires_at > ?)
                """,
                Long.class,
                account.getId().toString(),
                Timestamp.from(Instant.now())
        );

        return activeTokens != null && activeTokens > 0;
    }
}
