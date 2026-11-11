package com.NgariTech.identity_service.auth.google;

import com.NgariTech.identity_service.auth.CreatedMobileGoogleLoginCode;
import com.NgariTech.identity_service.auth.MobileGoogleLoginCodeService;
import com.NgariTech.identity_service.security.IamUserPrincipalService;
import com.NgariTech.identity_service.user.UserAccount;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.UUID;

@Component
@RequiredArgsConstructor
public class GoogleOAuth2SuccessHandler implements AuthenticationSuccessHandler {

    private static final Logger log = LoggerFactory.getLogger(GoogleOAuth2SuccessHandler.class);

    private final GoogleFederationService googleFederationService;
    private final IamUserPrincipalService iamUserPrincipalService;
    private final GoogleOAuth2FailureHandler failureHandler;
    private final MobileGoogleLoginCodeService mobileGoogleLoginCodeService;
    private final SecurityContextRepository securityContextRepository = new HttpSessionSecurityContextRepository();

    @Override
    public void onAuthenticationSuccess(
            HttpServletRequest request,
            HttpServletResponse response,
            Authentication authentication
    ) throws IOException, ServletException {
        Object principal = authentication.getPrincipal();
        if (!(principal instanceof OidcUser oidcUser)) {
            log.warn(
                    "mobile.google.oauth.success.invalid_principal principalType={}",
                    principal == null ? "null" : principal.getClass().getName()
            );
            failureHandler.onAuthenticationFailure(
                    request,
                    response,
                    new GoogleAuthenticationException("Google authentication could not be completed")
            );
            return;
        }

        HttpSession session = request.getSession(false);
        String mobileTraceId = mobileTraceId(session);
        try {
            UUID challengeId = challengeId(session);
            String mobileRedirectUri = mobileRedirectUri(session);
            log.info(
                    "mobile.google.oauth.success.received traceId={} mobileFlow={} challengePresent={} sessionPresent={}",
                    value(mobileTraceId),
                    mobileRedirectUri != null,
                    challengeId != null,
                    session != null
            );
            UserAccount account = mobileRedirectUri != null
                    ? googleFederationService.authenticateMobile(
                            oidcUser,
                            challengeId,
                            sourceIp(request),
                            request.getHeader("User-Agent")
                    )
                    : googleFederationService.authenticate(
                            oidcUser,
                            challengeId,
                            sourceIp(request),
                            request.getHeader("User-Agent")
                    );
            clearSessionState(session);

            if (mobileRedirectUri != null) {
                CreatedMobileGoogleLoginCode code = mobileGoogleLoginCodeService.create(account, mobileRedirectUri, mobileTraceId);
                log.info(
                        "mobile.google.oauth.success.redirect traceId={} userId={} codeExpiresAt={}",
                        value(mobileTraceId),
                        account.getId(),
                        code.expiresAt()
                );
                response.sendRedirect(code.redirectUrl());
                return;
            }

            UserDetails userDetails = iamUserPrincipalService.userDetails(account);
            UsernamePasswordAuthenticationToken localAuthentication = UsernamePasswordAuthenticationToken.authenticated(
                    userDetails,
                    "GOOGLE",
                    userDetails.getAuthorities()
            );
            localAuthentication.setDetails(authentication.getDetails());

            SecurityContext context = SecurityContextHolder.createEmptyContext();
            context.setAuthentication(localAuthentication);
            SecurityContextHolder.setContext(context);
            securityContextRepository.saveContext(context, request, response);
            response.sendRedirect("/api/v1/auth/channel/success");
        }
        catch (GoogleAuthenticationException exception) {
            SecurityContextHolder.clearContext();
            log.warn(
                    "mobile.google.oauth.success.rejected traceId={} reason={}",
                    value(mobileTraceId),
                    exception.getMessage()
            );
            failureHandler.onAuthenticationFailure(request, response, exception);
        }
    }

    private UUID challengeId(HttpSession session) {
        if (session == null) {
            return null;
        }

        Object value = session.getAttribute(GoogleLoginSession.CHANNEL_LINK_CHALLENGE_ID);
        if (value instanceof UUID uuid) {
            return uuid;
        }

        if (value instanceof String text && !text.isBlank()) {
            try {
                return UUID.fromString(text);
            }
            catch (IllegalArgumentException ignored) {
                return null;
            }
        }

        return null;
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

    private void clearSessionState(HttpSession session) {
        if (session != null) {
            session.removeAttribute(GoogleLoginSession.CHANNEL_LINK_CHALLENGE_ID);
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
