package com.NgariTech.identity_service.auth.oidc;

import com.NgariTech.identity_service.auth.AuditEventType;
import com.NgariTech.identity_service.auth.AuditLogService;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AccessTokenAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.web.authentication.OAuth2AccessTokenResponseAuthenticationSuccessHandler;
import org.springframework.security.oauth2.server.authorization.web.authentication.OAuth2ErrorAuthenticationFailureHandler;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
@RequiredArgsConstructor
public class OAuth2EndpointAuditHandlers {

    private final AuditLogService auditLogService;
    private final AuthenticationSuccessHandler tokenSuccessDelegate =
            new OAuth2AccessTokenResponseAuthenticationSuccessHandler();
    private final AuthenticationFailureHandler errorDelegate =
            new OAuth2ErrorAuthenticationFailureHandler();

    public void onTokenSuccess(
            HttpServletRequest request,
            HttpServletResponse response,
            Authentication authentication
    ) throws IOException, ServletException {
        if (authentication instanceof OAuth2AccessTokenAuthenticationToken accessTokenAuthentication) {
            String grantType = request.getParameter(OAuth2ParameterNames.GRANT_TYPE);
            String clientId = accessTokenAuthentication.getRegisteredClient().getClientId();

            if (AuthorizationGrantType.REFRESH_TOKEN.getValue().equals(grantType)) {
                auditLogService.record(
                        AuditEventType.REFRESH_SUCCESS,
                        null,
                        null,
                        sourceIp(request),
                        userAgent(request),
                        "Refresh token rotated for client " + clientId
                );
            }
            else {
                auditLogService.recordSystem(
                        AuditEventType.TOKEN_ISSUED,
                        "OAuth2 token issued using " + grantType + " for client " + clientId
                );
            }
        }

        tokenSuccessDelegate.onAuthenticationSuccess(request, response, authentication);
    }

    public void onTokenFailure(
            HttpServletRequest request,
            HttpServletResponse response,
            AuthenticationException exception
    ) throws IOException, ServletException {
        String grantType = request.getParameter(OAuth2ParameterNames.GRANT_TYPE);
        AuditEventType eventType = AuthorizationGrantType.REFRESH_TOKEN.getValue().equals(grantType)
                ? AuditEventType.REFRESH_FAILURE
                : AuditEventType.TOKEN_FAILURE;

        auditLogService.record(
                eventType,
                null,
                clientId(request),
                sourceIp(request),
                userAgent(request),
                "OAuth2 token request failed"
        );

        errorDelegate.onAuthenticationFailure(request, response, exception);
    }

    public void onRevocationSuccess(
            HttpServletRequest request,
            HttpServletResponse response,
            Authentication authentication
    ) {
        auditLogService.record(
                AuditEventType.LOGOUT,
                null,
                clientId(request),
                sourceIp(request),
                userAgent(request),
                "OAuth2 token revoked"
        );

        response.setStatus(HttpStatus.OK.value());
    }

    public void onRevocationFailure(
            HttpServletRequest request,
            HttpServletResponse response,
            AuthenticationException exception
    ) throws IOException, ServletException {
        auditLogService.record(
                AuditEventType.TOKEN_FAILURE,
                null,
                clientId(request),
                sourceIp(request),
                userAgent(request),
                "OAuth2 token revocation failed"
        );

        errorDelegate.onAuthenticationFailure(request, response, exception);
    }

    private String clientId(HttpServletRequest request) {
        String clientId = request.getParameter(OAuth2ParameterNames.CLIENT_ID);
        return clientId == null || clientId.isBlank() ? null : clientId;
    }

    private String sourceIp(HttpServletRequest request) {
        String forwardedFor = request.getHeader("X-Forwarded-For");
        if (forwardedFor != null && !forwardedFor.isBlank()) {
            return forwardedFor.split(",")[0].trim();
        }

        return request.getRemoteAddr();
    }

    private String userAgent(HttpServletRequest request) {
        return request.getHeader("User-Agent");
    }
}
