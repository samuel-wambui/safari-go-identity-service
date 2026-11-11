package com.NgariTech.identity_service.auth;

import com.NgariTech.identity_service.email.IdentityEmailSender;
import com.NgariTech.identity_service.auth.channel.ChannelAuthenticationService;
import com.NgariTech.identity_service.auth.channel.ChannelLinkChallenge;
import com.NgariTech.identity_service.auth.channel.ChannelLinkChallengeException;
import com.NgariTech.identity_service.auth.channel.ChannelLinkChallengeService;
import com.NgariTech.identity_service.auth.google.GoogleLoginSession;
import com.NgariTech.identity_service.security.IamUserPrincipalService;
import com.NgariTech.identity_service.user.UserAccount;
import com.NgariTech.identity_service.user.UserRepository;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.FactorGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.WebAttributes;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collection;
import java.util.Locale;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class LoginVerificationService {

    private static final String DEFAULT_SUCCESS_URL = "/login/success";
    private static final String GENERIC_ERROR = "Invalid credentials or account unavailable";
    private static final String HASH_PREFIX = "sha256:";
    private static final int MAX_CODE_ATTEMPTS = 4;
    private static final String PENDING_USER_ID = LoginVerificationService.class.getName() + ".USER_ID";
    private static final String PENDING_EMAIL = LoginVerificationService.class.getName() + ".EMAIL";
    private static final String PENDING_CODE_HASH = LoginVerificationService.class.getName() + ".CODE_HASH";
    private static final String PENDING_EXPIRES_AT = LoginVerificationService.class.getName() + ".EXPIRES_AT";
    private static final String PENDING_ATTEMPTS = LoginVerificationService.class.getName() + ".ATTEMPTS";

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final LoginAttemptService loginAttemptService;
    private final AuthenticationRateLimiter authenticationRateLimiter;
    private final IamUserPrincipalService iamUserPrincipalService;
    private final VerificationCodeGenerator verificationCodeGenerator;
    private final IdentityEmailSender emailSender;
    private final ChannelLinkChallengeService channelLinkChallengeService;
    private final ChannelAuthenticationService channelAuthenticationService;
    private final SecurityContextRepository securityContextRepository = new HttpSessionSecurityContextRepository();
    private final RequestCache requestCache = new HttpSessionRequestCache();

    @Value("${iam.login-verification.code-minutes:10}")
    private long codeMinutes;

    @Transactional(readOnly = true)
    public void startPasswordLogin(String username, String password, HttpServletRequest request) {
        String email = normalizeEmail(username);
        String sourceIp = sourceIp(request);
        String userAgent = userAgent(request);

        if (!authenticationRateLimiter.isAllowed(email, sourceIp)) {
            loginAttemptService.recordRateLimitFailure(email, sourceIp, userAgent);
            throw new LockedException(GENERIC_ERROR);
        }

        loginAttemptService.unlockIfExpired(email, sourceIp, userAgent);

        UserAccount account = userRepository.findByEmailIgnoreCaseAndDeletedFalse(email)
                .orElseThrow(() -> rejectBadCredentials(email, sourceIp, userAgent));

        if (!account.isPasswordLoginEnabled()) {
            throw rejectBadCredentials(email, sourceIp, userAgent);
        }

        if (!account.isEnabled()) {
            loginAttemptService.recordGenericFailure(email, sourceIp, userAgent, "Authentication failed while account unavailable");
            throw new DisabledException(GENERIC_ERROR);
        }

        if (!account.isAccountNonLocked()) {
            loginAttemptService.recordGenericFailure(email, sourceIp, userAgent, "Authentication failed while account unavailable");
            throw new LockedException(GENERIC_ERROR);
        }

        if (password == null || !passwordEncoder.matches(password, account.getPassword())) {
            throw rejectBadCredentials(email, sourceIp, userAgent);
        }

        requireMatchingWhatsappChallenge(request.getSession(false), account, sourceIp, userAgent);

        String code = verificationCodeGenerator.generate();
        Instant expiresAt = Instant.now().plus(Duration.ofMinutes(codeMinutes));
        HttpSession session = request.getSession(true);
        session.setAttribute(PENDING_USER_ID, account.getId().toString());
        session.setAttribute(PENDING_EMAIL, account.getEmail());
        session.setAttribute(PENDING_CODE_HASH, hash(code));
        session.setAttribute(PENDING_EXPIRES_AT, expiresAt);
        session.setAttribute(PENDING_ATTEMPTS, 0);
        session.removeAttribute(WebAttributes.AUTHENTICATION_EXCEPTION);

        emailSender.sendEmailWithVerificationCode(
                account.getEmail(),
                "SafariGo sign-in verification code",
                loginCodeMessage(code, expiresAt)
        );
    }

    public PendingLogin pendingLogin(HttpSession session) {
        if (!hasPendingLogin(session)) {
            return null;
        }

        return new PendingLogin(maskEmail((String) session.getAttribute(PENDING_EMAIL)));
    }

    public boolean hasPendingLogin(HttpSession session) {
        if (session == null) {
            return false;
        }

        Instant expiresAt = (Instant) session.getAttribute(PENDING_EXPIRES_AT);
        if (expiresAt == null || !Instant.now().isBefore(expiresAt)) {
            clearPendingLogin(session);
            return false;
        }

        return session.getAttribute(PENDING_USER_ID) != null
                && session.getAttribute(PENDING_EMAIL) != null
                && session.getAttribute(PENDING_CODE_HASH) != null;
    }

    @Transactional
    public String completeLogin(String code, HttpServletRequest request, HttpServletResponse response) {
        HttpSession session = request.getSession(false);
        if (!hasPendingLogin(session)) {
            throw new BadCredentialsException(GENERIC_ERROR);
        }

        String email = (String) session.getAttribute(PENDING_EMAIL);
        String expectedHash = (String) session.getAttribute(PENDING_CODE_HASH);
        String sourceIp = sourceIp(request);
        String userAgent = userAgent(request);

        if (code == null || !hashMatches(code.trim(), expectedHash)) {
            recordCodeFailure(session, email, sourceIp, userAgent);
            throw new BadCredentialsException(GENERIC_ERROR);
        }

        UUID userId = UUID.fromString((String) session.getAttribute(PENDING_USER_ID));
        UserAccount account = userRepository.findByIdAndDeletedFalse(userId)
                .filter(UserAccount::isEnabled)
                .filter(UserAccount::isAccountNonLocked)
                .filter(UserAccount::isPasswordLoginEnabled)
                .orElseThrow(() -> new BadCredentialsException(GENERIC_ERROR));

        boolean whatsappChallengeCompleted = completeWhatsappChallengeIfPresent(session, account, sourceIp, userAgent);

        UserDetails userDetails = iamUserPrincipalService.userDetails(account);
        Collection<GrantedAuthority> authorities = new ArrayList<>(userDetails.getAuthorities());
        authorities.add(FactorGrantedAuthority.withAuthority(FactorGrantedAuthority.PASSWORD_AUTHORITY)
                .issuedAt(Instant.now())
                .build());

        UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
                userDetails,
                null,
                authorities
        );
        authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

        SecurityContext context = SecurityContextHolder.createEmptyContext();
        context.setAuthentication(authentication);
        SecurityContextHolder.setContext(context);
        securityContextRepository.saveContext(context, request, response);

        authenticationRateLimiter.recordSuccess(account.getEmail());
        loginAttemptService.recordSuccessByUserId(account.getId().toString(), sourceIp, userAgent);
        clearPendingLogin(session);

        if (whatsappChallengeCompleted) {
            return "/api/v1/auth/channel/success";
        }

        SavedRequest savedRequest = requestCache.getRequest(request, response);
        if (savedRequest == null) {
            return DEFAULT_SUCCESS_URL;
        }

        requestCache.removeRequest(request, response);
        return savedRequest.getRedirectUrl();
    }

    private void requireMatchingWhatsappChallenge(
            HttpSession session,
            UserAccount account,
            String sourceIp,
            String userAgent
    ) {
        UUID challengeId = channelChallengeId(session);
        if (challengeId == null) {
            return;
        }

        try {
            ChannelLinkChallenge challenge = channelLinkChallengeService.requireUsable(challengeId, sourceIp, userAgent);
            if (!challenge.getPhoneNumber().equals(account.getPhoneNumber())) {
                throw new BadCredentialsException(GENERIC_ERROR);
            }
        }
        catch (ChannelLinkChallengeException exception) {
            throw new BadCredentialsException(GENERIC_ERROR);
        }
    }

    private boolean completeWhatsappChallengeIfPresent(
            HttpSession session,
            UserAccount account,
            String sourceIp,
            String userAgent
    ) {
        UUID challengeId = channelChallengeId(session);
        if (challengeId == null) {
            return false;
        }

        try {
            ChannelLinkChallenge challenge = channelLinkChallengeService.requireUsableForUpdate(challengeId, sourceIp, userAgent);
            if (!challenge.getPhoneNumber().equals(account.getPhoneNumber())) {
                throw new BadCredentialsException(GENERIC_ERROR);
            }

            channelLinkChallengeService.consumeLoaded(challenge);
            channelAuthenticationService.recordWhatsappAuthentication(
                    account,
                    challenge.getPhoneNumber(),
                    sourceIp,
                    userAgent
            );
            clearWhatsappChallenge(session);
            return true;
        }
        catch (ChannelLinkChallengeException exception) {
            throw new BadCredentialsException(GENERIC_ERROR);
        }
    }

    private UUID channelChallengeId(HttpSession session) {
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

    private void clearWhatsappChallenge(HttpSession session) {
        if (session != null) {
            session.removeAttribute(GoogleLoginSession.CHANNEL_LINK_CHALLENGE_ID);
        }
    }

    private BadCredentialsException rejectBadCredentials(String email, String sourceIp, String userAgent) {
        authenticationRateLimiter.recordFailure(email, sourceIp);
        loginAttemptService.recordFailure(email, sourceIp, userAgent);
        return new BadCredentialsException(GENERIC_ERROR);
    }

    private void recordCodeFailure(HttpSession session, String email, String sourceIp, String userAgent) {
        int attempts = session.getAttribute(PENDING_ATTEMPTS) instanceof Integer current ? current + 1 : 1;
        session.setAttribute(PENDING_ATTEMPTS, attempts);
        authenticationRateLimiter.recordFailure(email, sourceIp);
        loginAttemptService.recordFailure(email, sourceIp, userAgent);

        if (attempts >= MAX_CODE_ATTEMPTS) {
            clearPendingLogin(session);
        }
    }

    private void clearPendingLogin(HttpSession session) {
        if (session == null) {
            return;
        }

        session.removeAttribute(PENDING_USER_ID);
        session.removeAttribute(PENDING_EMAIL);
        session.removeAttribute(PENDING_CODE_HASH);
        session.removeAttribute(PENDING_EXPIRES_AT);
        session.removeAttribute(PENDING_ATTEMPTS);
    }

    private String loginCodeMessage(String code, Instant expiresAt) {
        return "Use this SafariGo sign-in verification code:\n\n"
                + code
                + "\n\nThis code expires at " + expiresAt + ". If you did not request it, ignore this email.";
    }

    private String normalizeEmail(String email) {
        if (email == null || email.isBlank()) {
            throw new BadCredentialsException(GENERIC_ERROR);
        }

        return email.trim().toLowerCase(Locale.ROOT);
    }

    private boolean hashMatches(String rawCode, String expectedHash) {
        byte[] left = hash(rawCode).getBytes(StandardCharsets.UTF_8);
        byte[] right = expectedHash.getBytes(StandardCharsets.UTF_8);
        return MessageDigest.isEqual(left, right);
    }

    private String hash(String value) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(value.getBytes(StandardCharsets.UTF_8));
            return HASH_PREFIX + Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
        }
        catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException("SHA-256 digest is unavailable", exception);
        }
    }

    private String maskEmail(String email) {
        if (email == null || email.isBlank()) {
            return "your email";
        }

        int at = email.indexOf('@');
        if (at <= 1) {
            return "***" + (at >= 0 ? email.substring(at) : "");
        }

        return email.charAt(0) + "***" + email.substring(at);
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

    public record PendingLogin(String maskedEmail) {
    }
}
