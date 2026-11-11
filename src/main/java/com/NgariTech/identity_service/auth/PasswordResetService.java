package com.NgariTech.identity_service.auth;

import com.NgariTech.identity_service.auth.dto.ResetPasswordRequest;
import com.NgariTech.identity_service.auth.oidc.AuthorizationRevocationService;
import com.NgariTech.identity_service.email.IdentityEmailSender;
import com.NgariTech.identity_service.user.UserAccount;
import com.NgariTech.identity_service.user.UserRepository;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.util.UriComponentsBuilder;

import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Locale;
import java.util.Optional;

@Service
@RequiredArgsConstructor
public class PasswordResetService {

    private static final Logger log = LoggerFactory.getLogger(PasswordResetService.class);
    private static final String HASH_PREFIX = "sha256:";
    private static final int TOKEN_BYTES = 32;
    private static final String GENERIC_RESET_ERROR = "Reset link is invalid or expired";

    private final UserRepository userRepository;
    private final PasswordResetTokenRepository tokenRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuthorizationRevocationService authorizationRevocationService;
    private final AuditLogService auditLogService;
    private final IdentityEmailSender emailSender;
    private final SecureRandom secureRandom = new SecureRandom();

    @Value("${iam.password-reset.token-minutes:30}")
    private long tokenMinutes;

    @Value("${iam.public-base-url:http://localhost:8081}")
    private String publicBaseUrl;

    @Transactional
    public void requestReset(String email, String sourceIp, String userAgent, String requestBaseUrl) {
        if (email == null || email.isBlank()) {
            return;
        }

        Optional<UserAccount> account = userRepository.findByEmailIgnoreCaseAndDeletedFalse(normalizeEmail(email))
                .filter(UserAccount::isEnabled)
                .filter(UserAccount::isPasswordLoginEnabled);

        if (account.isEmpty()) {
            auditLogService.record(
                    AuditEventType.PASSWORD_CHANGE,
                    null,
                    normalizeEmail(email),
                    sourceIp,
                    userAgent,
                    "Password reset requested"
            );
            return;
        }

        String rawToken = newToken();
        Instant now = Instant.now();
        Instant expiresAt = now.plus(Duration.ofMinutes(tokenMinutes));

        tokenRepository.markActiveTokensUsed(account.get().getId(), now);

        PasswordResetToken resetToken = new PasswordResetToken();
        resetToken.setUser(account.get());
        resetToken.setTokenHash(hash(rawToken));
        resetToken.setExpiresAt(expiresAt);
        tokenRepository.save(resetToken);

        emailSender.sendEmailWithVerificationCode(
                account.get().getEmail(),
                "SafariGo password reset",
                passwordResetMessage(resetUrl(rawToken, requestBaseUrl), expiresAt)
        );

        auditLogService.record(
                AuditEventType.PASSWORD_CHANGE,
                account.get().getId(),
                account.get().getEmail(),
                sourceIp,
                userAgent,
                "Password reset link sent"
        );
    }

    @Transactional(readOnly = true)
    public boolean isTokenUsable(String rawToken) {
        if (rawToken == null || rawToken.isBlank()) {
            return false;
        }

        return tokenRepository.findByTokenHash(hash(rawToken.trim()))
                .filter(this::isUsable)
                .map(PasswordResetToken::getUser)
                .filter(UserAccount::isEnabled)
                .filter(user -> !user.isDeleted())
                .filter(UserAccount::isPasswordLoginEnabled)
                .isPresent();
    }

    @Transactional
    public void resetPassword(ResetPasswordRequest request, String sourceIp, String userAgent) {
        PasswordResetToken token = tokenRepository.findForUpdateByTokenHash(hash(request.token().trim()))
                .filter(this::isUsable)
                .orElseThrow(() -> new BadCredentialsException(GENERIC_RESET_ERROR));

        UserAccount account = token.getUser();
        if (!account.isEnabled() || account.isDeleted() || !account.isPasswordLoginEnabled()) {
            throw new BadCredentialsException(GENERIC_RESET_ERROR);
        }

        account.setPassword(passwordEncoder.encode(request.password()));
        account.setFailedLoginAttempts(0);
        account.setAccountNonLocked(true);
        account.setLockedAt(null);
        account.setLockExpiresAt(null);
        account.setLastFailedLoginAt(null);
        token.setUsedAt(Instant.now());

        authorizationRevocationService.revokeAllForUser(account);
        auditLogService.record(
                AuditEventType.PASSWORD_CHANGE,
                account.getId(),
                account.getEmail(),
                sourceIp,
                userAgent,
                "Password reset completed and refresh tokens revoked"
        );
    }

    private boolean isUsable(PasswordResetToken token) {
        return token.getUsedAt() == null
                && token.getExpiresAt() != null
                && Instant.now().isBefore(token.getExpiresAt());
    }

    private String passwordResetMessage(String resetUrl, Instant expiresAt) {
        return "Use this SafariGo password reset link:\n\n"
                + resetUrl
                + "\n\nThis link expires at " + expiresAt + ". If you did not request it, ignore this email.";
    }

    private String resetUrl(String rawToken, String requestBaseUrl) {
        String baseUrl = resetBaseUrl(requestBaseUrl);

        return UriComponentsBuilder.fromUriString(baseUrl)
                .path("/reset-password")
                .queryParam("token", rawToken)
                .build()
                .toUriString();
    }

    private String resetBaseUrl(String requestBaseUrl) {
        Optional<String> resolvedRequestBaseUrl = normalizedRequestBaseUrl(requestBaseUrl);
        if (resolvedRequestBaseUrl.isPresent()) {
            log.info("Using password reset base URL from request host: baseUrl={}", resolvedRequestBaseUrl.get());
            return resolvedRequestBaseUrl.get();
        }

        String fallbackBaseUrl = normalizedBaseUrl(publicBaseUrl).orElseThrow();
        log.info(
                "Using password reset base URL from configured public base URL: baseUrl={}, ignoredRequestBaseUrl={}",
                fallbackBaseUrl,
                requestBaseUrl
        );
        return fallbackBaseUrl;
    }

    private Optional<String> normalizedRequestBaseUrl(String value) {
        return normalizedBaseUrl(value)
                .filter(baseUrl -> !isLocalBaseUrl(baseUrl));
    }

    private Optional<String> normalizedBaseUrl(String value) {
        if (value == null || value.isBlank()) {
            return Optional.empty();
        }

        String baseUrl = value.trim();
        return Optional.of(baseUrl.endsWith("/")
                ? baseUrl.substring(0, baseUrl.length() - 1)
                : baseUrl);
    }

    private boolean isLocalBaseUrl(String value) {
        try {
            URI uri = new URI(value);
            String host = uri.getHost();
            if (host == null || host.isBlank()) {
                return true;
            }

            return isLocalHost(host);
        }
        catch (URISyntaxException exception) {
            return true;
        }
    }

    private boolean isLocalHost(String host) {
        String normalizedHost = host.trim().toLowerCase(Locale.ROOT);
        if (normalizedHost.startsWith("[") && normalizedHost.endsWith("]")) {
            normalizedHost = normalizedHost.substring(1, normalizedHost.length() - 1);
        }

        return normalizedHost.equals("localhost")
                || normalizedHost.endsWith(".localhost")
                || normalizedHost.equals("host.docker.internal")
                || normalizedHost.equals("0.0.0.0")
                || normalizedHost.startsWith("127.")
                || normalizedHost.equals("::1")
                || normalizedHost.equals("0:0:0:0:0:0:0:1");
    }

    private String newToken() {
        byte[] bytes = new byte[TOKEN_BYTES];
        secureRandom.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private String normalizeEmail(String email) {
        return email.trim().toLowerCase(Locale.ROOT);
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
}
