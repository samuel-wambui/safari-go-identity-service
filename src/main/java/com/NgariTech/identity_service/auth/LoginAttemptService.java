package com.NgariTech.identity_service.auth;

import com.NgariTech.identity_service.auth.oidc.AuthorizationRevocationService;
import com.NgariTech.identity_service.user.UserAccount;
import com.NgariTech.identity_service.user.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import java.time.Duration;
import java.time.Instant;

@Service
@RequiredArgsConstructor
public class LoginAttemptService {

    private static final int MAX_ATTEMPTS = 4;
    private static final Duration LOCK_DURATION = Duration.ofMinutes(30);

    private final UserRepository userRepository;
    private final AuditLogService auditLogService;
    private final AuthorizationRevocationService authorizationRevocationService;

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void recordFailure(String email, String sourceIp, String userAgent) {
        userRepository.findForLoginUpdate(email)
                .ifPresentOrElse(account -> recordFailureForAccount(account, email, sourceIp, userAgent), () ->
                        auditLogService.record(
                                AuditEventType.LOGIN_FAILURE,
                                null,
                                email,
                                sourceIp,
                                userAgent,
                                "Authentication failed"
                        )
                );
    }

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void recordSuccess(String email, String sourceIp, String userAgent) {
        userRepository.findForLoginUpdate(email)
                .ifPresent(account -> {
                    resetAfterSuccess(account);
                    recordLoginSuccess(account, sourceIp, userAgent);
                });
    }

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void recordSuccessByUserId(String userId, String sourceIp, String userAgent) {
        try {
            userRepository.findByIdAndDeletedFalse(java.util.UUID.fromString(userId))
                    .ifPresent(account -> {
                        resetAfterSuccess(account);
                        recordLoginSuccess(account, sourceIp, userAgent);
                    });
        }
        catch (IllegalArgumentException exception) {
            auditLogService.record(
                    AuditEventType.LOGIN_SUCCESS,
                    null,
                    null,
                    sourceIp,
                    userAgent,
                    "Authentication succeeded"
            );
        }
    }

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void recordGenericFailure(String principal, String sourceIp, String userAgent, String details) {
        auditLogService.record(
                AuditEventType.LOGIN_FAILURE,
                null,
                principal,
                sourceIp,
                userAgent,
                details
        );
    }

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void recordFailureForUser(UserAccount account, String principal, String sourceIp, String userAgent) {
        userRepository.findByIdAndDeletedFalse(account.getId())
                .ifPresentOrElse(lockedAccount -> recordFailureForAccount(lockedAccount, principal, sourceIp, userAgent), () ->
                        auditLogService.record(
                                AuditEventType.LOGIN_FAILURE,
                                account.getId(),
                                principal,
                                sourceIp,
                                userAgent,
                                "Authentication failed"
                        )
                );
    }

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void recordRateLimitFailure(String email, String sourceIp, String userAgent) {
        auditLogService.record(
                AuditEventType.LOGIN_FAILURE,
                null,
                email,
                sourceIp,
                userAgent,
                "Authentication rate limit exceeded"
        );
    }

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void unlockIfExpiredByUserId(String userId, String sourceIp, String userAgent) {
        try {
            userRepository.findByIdAndDeletedFalse(java.util.UUID.fromString(userId))
                    .ifPresent(account -> unlockIfExpired(account, sourceIp, userAgent));
        }
        catch (IllegalArgumentException ignored) {
        }
    }

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void lockUser(UserAccount account, String sourceIp, String userAgent) {
        Instant now = Instant.now();
        account.setAccountNonLocked(false);
        account.setLockedAt(now);
        account.setLockExpiresAt(now.plus(LOCK_DURATION));
        authorizationRevocationService.revokeAllForUser(account);

        auditLogService.record(
                AuditEventType.ACCOUNT_LOCKED,
                account.getId(),
                account.getEmail(),
                sourceIp,
                userAgent,
                "Account locked after failed login attempts"
        );
    }

    private void resetAfterSuccess(UserAccount account) {
        account.setFailedLoginAttempts(0);
        account.setAccountNonLocked(true);
        account.setLockedAt(null);
        account.setLockExpiresAt(null);
        account.setLastFailedLoginAt(null);
        account.setLastLoginAt(Instant.now());
        account.setLastAuthenticationMethod("PASSWORD");
    }

    private void recordLoginSuccess(UserAccount account, String sourceIp, String userAgent) {
        auditLogService.record(
                AuditEventType.LOGIN_SUCCESS,
                account.getId(),
                account.getEmail(),
                sourceIp,
                userAgent,
                "Authentication succeeded"
        );
    }

    private void unlockIfExpired(UserAccount account, String sourceIp, String userAgent) {
        Instant lockExpiry = account.getLockExpiresAt();

        if (!account.isAccountNonLocked()
                && lockExpiry != null
                && !Instant.now().isBefore(lockExpiry)) {

            account.setAccountNonLocked(true);
            account.setFailedLoginAttempts(0);
            account.setLockedAt(null);
            account.setLockExpiresAt(null);

            auditLogService.record(
                    AuditEventType.ACCOUNT_UNLOCKED,
                    account.getId(),
                    account.getEmail(),
                    sourceIp,
                    userAgent,
                    "Temporary login lock expired"
            );
        }
    }

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void unlockIfExpired(String email, String sourceIp, String userAgent) {
        userRepository.findForLoginUpdate(email)
                .ifPresent(account -> unlockIfExpired(account, sourceIp, userAgent));
    }

    private void recordFailureForAccount(
            UserAccount account,
            String email,
            String sourceIp,
            String userAgent
    ) {
        if (!account.isEnabled() || account.isDeleted()) {
            auditLogService.record(
                    AuditEventType.LOGIN_FAILURE,
                    account.getId(),
                    email,
                    sourceIp,
                    userAgent,
                    "Authentication failed"
            );
            return;
        }

        if (!account.isAccountNonLocked()) {
            auditLogService.record(
                    AuditEventType.LOGIN_FAILURE,
                    account.getId(),
                    email,
                    sourceIp,
                    userAgent,
                    "Authentication failed while account unavailable"
            );
            return;
        }

        Instant now = Instant.now();
        int attempts = account.getFailedLoginAttempts() + 1;

        account.setFailedLoginAttempts(attempts);
        account.setLastFailedLoginAt(now);

        auditLogService.record(
                AuditEventType.LOGIN_FAILURE,
                account.getId(),
                email,
                sourceIp,
                userAgent,
                "Authentication failed"
        );

        if (attempts >= MAX_ATTEMPTS) {
            lockUser(account, sourceIp, userAgent);
        }
    }
}
