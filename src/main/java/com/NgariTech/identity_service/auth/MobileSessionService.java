package com.NgariTech.identity_service.auth;

import com.NgariTech.identity_service.user.UserAccount;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class MobileSessionService {

    static final String SAFARIGO_MOBILE_CLIENT_ID = "safarigo-mobile";

    private final MobileSessionRepository mobileSessionRepository;
    private final AuditLogService auditLogService;

    public MobileSession create(UserAccount account, String authMethod, Instant expiresAt, HttpServletRequest request) {
        MobileSession session = new MobileSession();
        session.setUser(account);
        session.setClientId(SAFARIGO_MOBILE_CLIENT_ID);
        session.setAuthMethod(authMethod);
        session.setExpiresAt(expiresAt);
        session.setSourceIp(sourceIp(request));
        session.setUserAgent(userAgent(request));
        MobileSession saved = mobileSessionRepository.save(session);

        auditLogService.record(
                AuditEventType.MOBILE_SESSION_CREATED,
                account.getId(),
                account.getEmail(),
                sourceIp(request),
                userAgent(request),
                "Mobile session created: " + saved.getId()
        );

        return saved;
    }

    @Transactional
    public MobileSession revoke(UUID userId, UUID mobileSessionId, HttpServletRequest request) {
        MobileSession session = mobileSessionRepository.findByIdAndUser_Id(mobileSessionId, userId)
                .orElseThrow(() -> new BadCredentialsException("Invalid mobile session"));
        Instant now = Instant.now();
        boolean changed = session.getExpiresAt().isAfter(now)
                ? session.revoke(now)
                : session.expire(now);

        if (changed && session.getStatus() == MobileSessionStatus.REVOKED) {
            auditLogService.record(
                    AuditEventType.MOBILE_SESSION_REVOKED,
                    userId,
                    session.getUser().getEmail(),
                    sourceIp(request),
                    userAgent(request),
                    "Mobile session revoked: " + session.getId()
            );
        }

        return session;
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
}
