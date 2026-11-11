package com.NgariTech.identity_service.auth;

import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import java.util.UUID;

@Service
@RequiredArgsConstructor
public class AuditLogService {

    private final AuditLogRepository auditLogRepository;

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void record(
            AuditEventType eventType,
            UUID userId,
            String email,
            String sourceIp,
            String userAgent,
            String details
    ) {
        AuditLog auditLog = new AuditLog();
        auditLog.setEventType(eventType);
        auditLog.setUserId(userId);
        auditLog.setActorUserId(currentActorId());
        auditLog.setEmail(email);
        auditLog.setSourceIp(sourceIp);
        auditLog.setUserAgent(userAgent);
        auditLog.setDetails(details);
        auditLogRepository.save(auditLog);
    }

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void recordSystem(AuditEventType eventType, String details) {
        AuditLog auditLog = new AuditLog();
        auditLog.setEventType(eventType);
        auditLog.setActorUserId(currentActorId());
        auditLog.setDetails(details);
        auditLogRepository.save(auditLog);
    }

    private UUID currentActorId() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || authentication.getName() == null) {
            return null;
        }

        try {
            return UUID.fromString(authentication.getName());
        }
        catch (IllegalArgumentException exception) {
            return null;
        }
    }
}
