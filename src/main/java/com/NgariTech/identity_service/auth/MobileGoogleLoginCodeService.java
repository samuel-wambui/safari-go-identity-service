package com.NgariTech.identity_service.auth;

import com.NgariTech.identity_service.auth.dto.MobileLoginResponse;
import com.NgariTech.identity_service.user.UserAccount;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.util.UriComponentsBuilder;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Locale;

@Service
@RequiredArgsConstructor
public class MobileGoogleLoginCodeService {

    private static final String HASH_PREFIX = "sha256:";
    private static final int CODE_BYTES = 32;
    private static final String GENERIC_ERROR = "Google sign in is invalid or expired";
    private static final String SAFARIGO_GOOGLE_REDIRECT_URI = "safarigo://auth/google";
    private static final String TRACE_ID_HEADER = "X-SafariGo-Mobile-Trace-Id";
    private static final Logger log = LoggerFactory.getLogger(MobileGoogleLoginCodeService.class);

    private final MobileGoogleLoginCodeRepository codeRepository;
    private final MobileAuthenticationService mobileAuthenticationService;
    private final AuditLogService auditLogService;
    private final SecureRandom secureRandom = new SecureRandom();

    @Value("${iam.oauth2.token.mobile-google-code-minutes:5}")
    private long codeMinutes;

    public String requireAllowedRedirectUri(String redirectUri) {
        if (redirectUri == null || redirectUri.isBlank()) {
            throw new IllegalArgumentException("redirectUri is required");
        }
        String normalized = redirectUri.trim();
        if (!SAFARIGO_GOOGLE_REDIRECT_URI.equals(normalized)) {
            throw new IllegalArgumentException("redirectUri is not allowed");
        }
        return normalized;
    }

    @Transactional
    public CreatedMobileGoogleLoginCode create(UserAccount account, String redirectUri) {
        return create(account, redirectUri, null);
    }

    @Transactional
    public CreatedMobileGoogleLoginCode create(UserAccount account, String redirectUri, String traceId) {
        String allowedRedirectUri = requireAllowedRedirectUri(redirectUri);
        String mobileTraceId = normalizeTraceId(traceId);
        String rawCode = newCode();
        Instant now = Instant.now();
        Instant expiresAt = now.plus(Duration.ofMinutes(codeMinutes));

        MobileGoogleLoginCode loginCode = new MobileGoogleLoginCode();
        loginCode.setUser(account);
        loginCode.setCodeHash(hash(rawCode));
        loginCode.setRedirectUri(allowedRedirectUri);
        loginCode.setExpiresAt(expiresAt);
        codeRepository.save(loginCode);
        log.info(
                "mobile.google.code.created traceId={} codeId={} userId={} expiresAt={}",
                value(mobileTraceId),
                loginCode.getId(),
                account.getId(),
                expiresAt
        );

        return new CreatedMobileGoogleLoginCode(
                rawCode,
                redirectWithCode(allowedRedirectUri, rawCode, mobileTraceId),
                expiresAt
        );
    }

    @Transactional
    public MobileLoginResponse exchange(String rawCode, HttpServletRequest request) {
        String mobileTraceId = traceId(request);
        log.info("mobile.google.exchange.start traceId={} codePresent={}", value(mobileTraceId), rawCode != null && !rawCode.isBlank());
        String normalizedCode = requireCode(rawCode);
        MobileGoogleLoginCode loginCode = codeRepository.findForUpdateByCodeHash(hash(normalizedCode))
                .orElseThrow(() -> {
                    log.warn("mobile.google.exchange.rejected traceId={} reason=code_not_found", value(mobileTraceId));
                    return new BadCredentialsException(GENERIC_ERROR);
                });

        Instant now = Instant.now();
        if (!loginCode.isUsableAt(now)) {
            if (loginCode.getStatus() == MobileGoogleLoginCodeStatus.ACTIVE) {
                loginCode.expire();
            }
            log.warn(
                    "mobile.google.exchange.rejected traceId={} codeId={} status={} expiredAt={}",
                    value(mobileTraceId),
                    loginCode.getId(),
                    loginCode.getStatus(),
                    loginCode.getExpiresAt()
            );
            throw new BadCredentialsException(GENERIC_ERROR);
        }

        UserAccount account = loginCode.getUser();
        if (!account.isEnabled() || account.isDeleted() || !account.isAccountNonLocked()) {
            log.warn(
                    "mobile.google.exchange.rejected traceId={} codeId={} userId={} reason=account_unavailable",
                    value(mobileTraceId),
                    loginCode.getId(),
                    account.getId()
            );
            throw new BadCredentialsException("Invalid credentials or account unavailable");
        }

        loginCode.consume(now);
        log.info(
                "mobile.google.exchange.code_consumed traceId={} codeId={} userId={}",
                value(mobileTraceId),
                loginCode.getId(),
                account.getId()
        );
        auditLogService.record(
                AuditEventType.TOKEN_ISSUED,
                account.getId(),
                account.getEmail(),
                sourceIp(request),
                request.getHeader("User-Agent"),
                "Mobile Google access token issued"
        );
        MobileLoginResponse response = mobileAuthenticationService.issueAccessToken(account, "MOBILE_GOOGLE", request);
        log.info(
                "mobile.google.exchange.success traceId={} userId={} mobileSessionId={} expiresAt={}",
                value(mobileTraceId),
                response.userId(),
                response.mobileSessionId(),
                response.expiresAt()
        );
        return response;
    }

    public String redirectWithError(String redirectUri, String error) {
        return redirectWithError(redirectUri, error, null);
    }

    public String redirectWithError(String redirectUri, String error, String traceId) {
        String allowedRedirectUri = requireAllowedRedirectUri(redirectUri);
        UriComponentsBuilder builder = UriComponentsBuilder.fromUriString(allowedRedirectUri)
                .queryParam("error", sanitizeError(error))
                .queryParamIfPresent("traceId", java.util.Optional.ofNullable(normalizeTraceId(traceId)));
        return builder.build().toUriString();
    }

    public String normalizeTraceId(String traceId) {
        if (traceId == null || traceId.isBlank()) {
            return null;
        }
        String normalized = traceId.trim();
        return normalized.matches("[A-Za-z0-9_-]{8,96}") ? normalized : null;
    }

    private String redirectWithCode(String redirectUri, String rawCode, String traceId) {
        UriComponentsBuilder builder = UriComponentsBuilder.fromUriString(redirectUri)
                .queryParam("code", rawCode)
                .queryParamIfPresent("traceId", java.util.Optional.ofNullable(normalizeTraceId(traceId)));
        return builder.build().toUriString();
    }

    private String requireCode(String rawCode) {
        if (rawCode == null || rawCode.isBlank()) {
            throw new BadCredentialsException(GENERIC_ERROR);
        }
        return rawCode.trim();
    }

    private String newCode() {
        byte[] bytes = new byte[CODE_BYTES];
        secureRandom.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private String hash(String tokenValue) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(tokenValue.getBytes(StandardCharsets.UTF_8));
            return HASH_PREFIX + Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
        }
        catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException("SHA-256 digest is unavailable", exception);
        }
    }

    private String sourceIp(HttpServletRequest request) {
        String forwardedFor = request.getHeader("X-Forwarded-For");
        if (forwardedFor != null && !forwardedFor.isBlank()) {
            return forwardedFor.split(",")[0].trim();
        }
        return request.getRemoteAddr();
    }

    private String traceId(HttpServletRequest request) {
        if (request == null) {
            return null;
        }
        return normalizeTraceId(request.getHeader(TRACE_ID_HEADER));
    }

    private String value(String value) {
        return value == null || value.isBlank() ? "missing" : value;
    }

    private String sanitizeError(String error) {
        if (error == null || error.isBlank()) {
            return "google_sign_in_failed";
        }
        String normalized = error.trim().toLowerCase(Locale.ROOT);
        return normalized.matches("[a-z0-9_-]{1,64}") ? normalized : "google_sign_in_failed";
    }

}
