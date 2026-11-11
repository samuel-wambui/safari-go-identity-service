package com.NgariTech.identity_service.auth;

import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.context.event.EventListener;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.authentication.event.AbstractAuthenticationFailureEvent;
import org.springframework.security.authentication.event.AuthenticationSuccessEvent;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

@Component
@RequiredArgsConstructor
public class AuthenticationAuditEventListener {

    private final LoginAttemptService loginAttemptService;
    private final AuthenticationRateLimiter authenticationRateLimiter;

    @EventListener
    public void onSuccess(AuthenticationSuccessEvent event) {
        Authentication authentication = event.getAuthentication();
        if (!(authentication.getPrincipal() instanceof UserDetails)) {
            return;
        }

        String userId = authentication.getName();
        loginAttemptService.recordSuccessByUserId(userId, sourceIp(), userAgent());
    }

    @EventListener
    public void onFailure(AbstractAuthenticationFailureEvent event) {
        Authentication authentication = event.getAuthentication();
        String principal = authentication == null ? null : authentication.getName();

        if (event.getException() instanceof BadCredentialsException) {
            if (principal != null && !principal.isBlank()) {
                authenticationRateLimiter.recordFailure(principal, sourceIp());
                loginAttemptService.recordFailure(principal, sourceIp(), userAgent());
            }
            return;
        }

        if (event.getException() instanceof LockedException || event.getException() instanceof DisabledException) {
            loginAttemptService.recordGenericFailure(
                    principal,
                    sourceIp(),
                    userAgent(),
                    "Authentication failed while account unavailable"
            );
        }
    }

    private String sourceIp() {
        HttpServletRequest request = currentRequest();
        if (request == null) {
            return null;
        }

        String forwardedFor = request.getHeader("X-Forwarded-For");
        if (forwardedFor != null && !forwardedFor.isBlank()) {
            return forwardedFor.split(",")[0].trim();
        }

        return request.getRemoteAddr();
    }

    private String userAgent() {
        HttpServletRequest request = currentRequest();
        return request == null ? null : request.getHeader("User-Agent");
    }

    private HttpServletRequest currentRequest() {
        if (RequestContextHolder.getRequestAttributes() instanceof ServletRequestAttributes attributes) {
            return attributes.getRequest();
        }

        return null;
    }
}
