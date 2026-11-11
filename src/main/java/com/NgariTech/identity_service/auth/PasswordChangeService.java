package com.NgariTech.identity_service.auth;

import com.NgariTech.identity_service.auth.dto.ChangePasswordRequest;
import com.NgariTech.identity_service.auth.oidc.AuthorizationRevocationService;
import com.NgariTech.identity_service.user.UserAccount;
import com.NgariTech.identity_service.user.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.UUID;

@Service
@RequiredArgsConstructor
public class PasswordChangeService {

    private static final String GENERIC_ERROR = "Invalid credentials or account unavailable";

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuthorizationRevocationService authorizationRevocationService;
    private final AuditLogService auditLogService;

    @Transactional
    public void changePassword(
            UUID userId,
            ChangePasswordRequest request,
            String sourceIp,
            String userAgent
    ) {
        UserAccount account = userRepository.findByIdAndDeletedFalse(userId)
                .filter(UserAccount::isEnabled)
                .filter(UserAccount::isAccountNonLocked)
                .orElseThrow(() -> new BadCredentialsException(GENERIC_ERROR));

        if (!passwordEncoder.matches(request.currentPassword(), account.getPassword())) {
            auditLogService.record(
                    AuditEventType.PASSWORD_CHANGE,
                    account.getId(),
                    account.getEmail(),
                    sourceIp,
                    userAgent,
                    "Password change rejected"
            );
            throw new BadCredentialsException(GENERIC_ERROR);
        }

        account.setPassword(passwordEncoder.encode(request.newPassword()));
        account.setFailedLoginAttempts(0);
        account.setLastFailedLoginAt(null);
        authorizationRevocationService.revokeAllForUser(account);

        auditLogService.record(
                AuditEventType.PASSWORD_CHANGE,
                account.getId(),
                account.getEmail(),
                sourceIp,
                userAgent,
                "Password changed and refresh tokens revoked"
        );
    }
}
