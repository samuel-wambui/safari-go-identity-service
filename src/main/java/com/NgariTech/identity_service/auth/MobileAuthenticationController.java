package com.NgariTech.identity_service.auth;

import com.NgariTech.identity_service.auth.dto.MobileLoginRequest;
import com.NgariTech.identity_service.auth.dto.MobileLoginResponse;
import com.NgariTech.identity_service.auth.dto.MobileGoogleExchangeRequest;
import com.NgariTech.identity_service.auth.dto.MobileLogoutResponse;
import com.NgariTech.identity_service.auth.google.GoogleLoginSession;
import com.NgariTech.identity_service.common.api.ApiResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;
import java.util.UUID;

@RestController
@RequestMapping("/api/v1/mobile/auth")
@RequiredArgsConstructor
public class MobileAuthenticationController {

    private static final String GOOGLE_AUTHORIZATION_URL = "/oauth2/authorization/google?prompt=select_account";
    private static final Logger log = LoggerFactory.getLogger(MobileAuthenticationController.class);

    private final MobileAuthenticationService mobileAuthenticationService;
    private final MobileGoogleLoginCodeService mobileGoogleLoginCodeService;
    private final MobileSessionService mobileSessionService;

    @PostMapping("/login")
    public ResponseEntity<ApiResponse<MobileLoginResponse>> login(
            @Valid @RequestBody MobileLoginRequest request,
            HttpServletRequest servletRequest
    ) {
        return ResponseEntity.ok(ApiResponse.success(
                "Mobile login successful",
                mobileAuthenticationService.login(request, servletRequest)
        ));
    }

    @GetMapping("/google/start")
    public void startGoogleLogin(
            @RequestParam("redirectUri") String redirectUri,
            @RequestParam(value = "traceId", required = false) String traceId,
            HttpServletRequest request,
            HttpServletResponse response
    ) throws IOException {
        String allowedRedirectUri = mobileGoogleLoginCodeService.requireAllowedRedirectUri(redirectUri);
        String mobileTraceId = mobileGoogleLoginCodeService.normalizeTraceId(traceId);
        HttpSession session = request.getSession(true);
        session.setAttribute(GoogleLoginSession.MOBILE_REDIRECT_URI, allowedRedirectUri);
        if (mobileTraceId != null) {
            session.setAttribute(GoogleLoginSession.MOBILE_TRACE_ID, mobileTraceId);
        }
        log.info(
                "mobile.google.start traceId={} redirectAllowed=true session={} sourceIpPresent={} userAgentPresent={}",
                value(mobileTraceId),
                shortValue(session.getId()),
                request.getRemoteAddr() != null,
                request.getHeader("User-Agent") != null
        );
        response.sendRedirect(GOOGLE_AUTHORIZATION_URL);
    }

    @PostMapping("/google/exchange")
    public ResponseEntity<ApiResponse<MobileLoginResponse>> exchangeGoogleLogin(
            @Valid @RequestBody MobileGoogleExchangeRequest request,
            HttpServletRequest servletRequest
    ) {
        return ResponseEntity.ok(ApiResponse.success(
                "Mobile Google login successful",
                mobileGoogleLoginCodeService.exchange(request.code(), servletRequest)
        ));
    }

    @PostMapping("/logout")
    public ResponseEntity<ApiResponse<MobileLogoutResponse>> logout(
            @AuthenticationPrincipal Jwt jwt,
            HttpServletRequest servletRequest
    ) {
        UUID userId = uuid(jwt == null ? null : jwt.getSubject(), "Invalid mobile user");
        UUID mobileSessionId = uuid(jwt.getClaimAsString("mobile_session_id"), "Invalid mobile session");
        MobileSession session = mobileSessionService.revoke(userId, mobileSessionId, servletRequest);

        return ResponseEntity.ok(ApiResponse.success(
                "Mobile logout processed",
                new MobileLogoutResponse(
                        userId,
                        session.getId(),
                        session.getStatus(),
                        session.getRevokedAt()
                )
        ));
    }

    private UUID uuid(String value, String message) {
        if (value == null || value.isBlank()) {
            throw new BadCredentialsException(message);
        }
        try {
            return UUID.fromString(value);
        }
        catch (IllegalArgumentException exception) {
            throw new BadCredentialsException(message);
        }
    }

    private String value(String value) {
        return value == null || value.isBlank() ? "missing" : value;
    }

    private String shortValue(String value) {
        if (value == null || value.length() <= 8) {
            return value;
        }
        return value.substring(0, 4) + "..." + value.substring(value.length() - 4);
    }
}
