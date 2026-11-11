package com.NgariTech.identity_service.auth.google;

import com.NgariTech.identity_service.auth.AuditEventType;
import com.NgariTech.identity_service.auth.AuditLogService;
import com.NgariTech.identity_service.auth.MobileGoogleLoginCodeService;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
@RequiredArgsConstructor
public class GoogleOAuth2FailureHandler implements AuthenticationFailureHandler {

    private static final Logger log = LoggerFactory.getLogger(GoogleOAuth2FailureHandler.class);

    private final AuditLogService auditLogService;
    private final MobileGoogleLoginCodeService mobileGoogleLoginCodeService;

    @Override
    public void onAuthenticationFailure(
            HttpServletRequest request,
            HttpServletResponse response,
            AuthenticationException exception
    ) throws IOException, ServletException {
        HttpSession session = request.getSession(false);
        String mobileRedirectUri = mobileRedirectUri(session);
        String mobileTraceId = mobileTraceId(session);
        clearMobileRedirect(session);
        log.warn(
                "mobile.google.oauth.failure traceId={} mobileFlow={} reason={}",
                value(mobileTraceId),
                mobileRedirectUri != null,
                exception.getMessage()
        );
        auditLogService.record(
                AuditEventType.GOOGLE_LOGIN_FAILURE,
                null,
                null,
                sourceIp(request),
                request.getHeader("User-Agent"),
                "Google authentication failed"
        );
        if (mobileRedirectUri != null) {
            response.sendRedirect(mobileGoogleLoginCodeService.redirectWithError(
                    mobileRedirectUri,
                    "google_sign_in_failed",
                    mobileTraceId
            ));
            return;
        }
        response.sendRedirect("/api/v1/auth/channel/failure");
    }

    private String mobileRedirectUri(HttpSession session) {
        if (session == null) {
            return null;
        }

        Object value = session.getAttribute(GoogleLoginSession.MOBILE_REDIRECT_URI);
        if (value instanceof String text && !text.isBlank()) {
            return text;
        }
        return null;
    }

    private String mobileTraceId(HttpSession session) {
        if (session == null) {
            return null;
        }

        Object value = session.getAttribute(GoogleLoginSession.MOBILE_TRACE_ID);
        if (value instanceof String text && !text.isBlank()) {
            return text;
        }
        return null;
    }

    private void clearMobileRedirect(HttpSession session) {
        if (session != null) {
            session.removeAttribute(GoogleLoginSession.MOBILE_REDIRECT_URI);
            session.removeAttribute(GoogleLoginSession.MOBILE_TRACE_ID);
        }
    }

    private String sourceIp(HttpServletRequest request) {
        String forwardedFor = request.getHeader("X-Forwarded-For");
        if (forwardedFor != null && !forwardedFor.isBlank()) {
            return forwardedFor.split(",")[0].trim();
        }

        return request.getRemoteAddr();
    }

    private String value(String value) {
        return value == null || value.isBlank() ? "missing" : value;
    }
}
