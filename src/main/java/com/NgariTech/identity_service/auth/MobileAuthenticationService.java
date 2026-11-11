package com.NgariTech.identity_service.auth;

import com.NgariTech.identity_service.auth.dto.MobileLoginRequest;
import com.NgariTech.identity_service.auth.dto.MobileLoginResponse;
import com.NgariTech.identity_service.auth.oidc.IamTokenClaimService;
import com.NgariTech.identity_service.user.PhoneNumberNormalizer;
import com.NgariTech.identity_service.user.UserAccount;
import com.NgariTech.identity_service.user.UserRepository;
import jakarta.servlet.http.HttpServletRequest;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.oidc.StandardClaimNames;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
public class MobileAuthenticationService {

    private static final String GENERIC_ERROR = "Invalid credentials or account unavailable";

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationRateLimiter authenticationRateLimiter;
    private final LoginAttemptService loginAttemptService;
    private final IamTokenClaimService tokenClaimService;
    private final AuditLogService auditLogService;
    private final JwtEncoder jwtEncoder;
    private final MobileSessionService mobileSessionService;

    @Value("${security.jwt.issuer}")
    private String issuer;

    @Value("${security.jwt.audience}")
    private String audience;

    @Value("${security.jwt.key-id}")
    private String keyId;

    @Value("${iam.oauth2.token.mobile-access-token-minutes:10}")
    private long mobileAccessTokenMinutes;

    @Transactional
    public MobileLoginResponse login(MobileLoginRequest request, HttpServletRequest servletRequest) {
        String phoneNumber = PhoneNumberNormalizer.normalize(request.phoneNumber());
        String sourceIp = sourceIp(servletRequest);
        String userAgent = userAgent(servletRequest);

        if (!authenticationRateLimiter.isAllowed(phoneNumber, sourceIp)) {
            loginAttemptService.recordRateLimitFailure(phoneNumber, sourceIp, userAgent);
            throw new BadCredentialsException(GENERIC_ERROR);
        }

        UserAccount account = userRepository.findByPhoneNumberAndDeletedFalse(phoneNumber)
                .or(() -> userRepository.findByNormalizedPhoneNumberAndDeletedFalse(phoneNumber))
                .orElseThrow(() -> reject(phoneNumber, sourceIp, userAgent));

        loginAttemptService.unlockIfExpiredByUserId(account.getId().toString(), sourceIp, userAgent);
        account = userRepository.findByIdAndDeletedFalse(account.getId())
                .orElseThrow(() -> reject(phoneNumber, sourceIp, userAgent));

        if (!account.isPasswordLoginEnabled()
                || !account.isEnabled()
                || !account.isAccountNonLocked()
                || request.password() == null
                || !passwordEncoder.matches(request.password(), account.getPassword())) {
            authenticationRateLimiter.recordFailure(phoneNumber, sourceIp);
            loginAttemptService.recordFailureForUser(account, phoneNumber, sourceIp, userAgent);
            throw new BadCredentialsException(GENERIC_ERROR);
        }

        authenticationRateLimiter.recordSuccess(phoneNumber);
        loginAttemptService.recordSuccessByUserId(account.getId().toString(), sourceIp, userAgent);

        auditLogService.record(
                AuditEventType.TOKEN_ISSUED,
                account.getId(),
                account.getEmail(),
                sourceIp,
                userAgent,
                "Mobile access token issued"
        );

        return issueAccessToken(account, "MOBILE_PASSWORD", servletRequest);
    }

    public MobileLoginResponse issueAccessToken(UserAccount account, String authMethod, HttpServletRequest servletRequest) {
        Instant issuedAt = Instant.now();
        Instant expiresAt = issuedAt.plus(Duration.ofMinutes(mobileAccessTokenMinutes));
        MobileSession mobileSession = mobileSessionService.create(account, authMethod, expiresAt, servletRequest);
        List<String> roles = tokenClaimService.roleNames(account);
        List<String> permissions = tokenClaimService.permissionNames(account);
        String fullName = (account.getFirstName() + " " + account.getLastName()).trim();

        JwtClaimsSet claims = JwtClaimsSet.builder()
                .issuer(issuer)
                .subject(account.getId().toString())
                .audience(List.of(audience))
                .issuedAt(issuedAt)
                .expiresAt(expiresAt)
                .id(UUID.randomUUID().toString())
                .claim("roles", roles)
                .claim("permissions", permissions)
                .claim("scope", permissions)
                .claim("client_id", "safarigo-mobile")
                .claim(StandardClaimNames.EMAIL, account.getEmail())
                .claim(StandardClaimNames.PHONE_NUMBER, account.getPhoneNumber())
                .claim(StandardClaimNames.GIVEN_NAME, account.getFirstName())
                .claim(StandardClaimNames.FAMILY_NAME, account.getLastName())
                .claim(StandardClaimNames.NAME, fullName)
                .claim("auth_method", authMethod)
                .claim("mobile_session_id", mobileSession.getId().toString())
                .build();

        String accessToken = jwtEncoder.encode(JwtEncoderParameters.from(
                JwsHeader.with(SignatureAlgorithm.RS256).keyId(keyId).build(),
                claims
        )).getTokenValue();

        return new MobileLoginResponse(
                account.getId(),
                mobileSession.getId(),
                account.getEmail(),
                account.getPhoneNumber(),
                account.getFirstName(),
                account.getLastName(),
                "Bearer",
                accessToken,
                Duration.between(issuedAt, expiresAt).toSeconds(),
                expiresAt
        );
    }

    private BadCredentialsException reject(String phoneNumber, String sourceIp, String userAgent) {
        authenticationRateLimiter.recordFailure(phoneNumber, sourceIp);
        loginAttemptService.recordGenericFailure(phoneNumber, sourceIp, userAgent, "Authentication failed");
        return new BadCredentialsException(GENERIC_ERROR);
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
