package com.NgariTech.identity_service.auth;

import com.NgariTech.identity_service.auth.dto.ChangePasswordRequest;
import com.NgariTech.identity_service.auth.dto.LogoutUserRequest;
import com.NgariTech.identity_service.auth.dto.LogoutUserResponse;
import com.NgariTech.identity_service.auth.channel.ChannelAuthenticationService;
import com.NgariTech.identity_service.auth.oidc.AuthorizationRevocationService;
import com.NgariTech.identity_service.auth.oidc.AuthorizationRevocationService.RevocationResult;
import com.NgariTech.identity_service.common.api.ApiResponse;
import com.NgariTech.identity_service.common.exception.ResourceNotFoundException;
import com.NgariTech.identity_service.user.PhoneNumberNormalizer;
import com.NgariTech.identity_service.user.UserAccount;
import com.NgariTech.identity_service.user.UserRepository;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Locale;
import java.util.UUID;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AccountController {

    private final PasswordChangeService passwordChangeService;
    private final AuthorizationRevocationService authorizationRevocationService;
    private final ChannelAuthenticationService channelAuthenticationService;
    private final UserRepository userRepository;
    private final AuditLogService auditLogService;

    @PostMapping("/logout")
    public ResponseEntity<ApiResponse<LogoutUserResponse>> logoutUser(
            @Valid @RequestBody LogoutUserRequest request,
            HttpServletRequest servletRequest
    ) {
        UserAccount account = resolveUser(request);
        RevocationResult result = authorizationRevocationService.revokeAllForUser(account);
        int revokedChannelAuthentications = channelAuthenticationService.revokeWhatsappAuthentications(
                account,
                sourceIp(servletRequest),
                userAgent(servletRequest)
        );

        auditLogService.record(
                AuditEventType.LOGOUT_ALL,
                account.getId(),
                account.getEmail(),
                sourceIp(servletRequest),
                userAgent(servletRequest),
                "User logout requested by identifier; active authorizations=%d, active refresh tokens=%d"
                        .formatted(result.activeAuthorizations(), result.activeRefreshTokens())
        );

        return ResponseEntity.ok(ApiResponse.success(
                "User logout processed",
                new LogoutUserResponse(
                        account.getId(),
                        account.getEmail(),
                        account.getPhoneNumber(),
                        result.activeAuthorizations(),
                        result.activeRefreshTokens(),
                        result.revokedAuthorizations(),
                        result.revokedRefreshTokens(),
                        revokedChannelAuthentications
                )
        ));
    }

    @PostMapping("/password")
    public ResponseEntity<ApiResponse<Void>> changePassword(
            @Valid @RequestBody ChangePasswordRequest request,
            Authentication authentication,
            HttpServletRequest servletRequest
    ) {
        passwordChangeService.changePassword(
                UUID.fromString(authentication.getName()),
                request,
                sourceIp(servletRequest),
                userAgent(servletRequest)
        );

        return ResponseEntity.ok(ApiResponse.success("Password changed", null));
    }

    @PostMapping("/logout-all")
    public ResponseEntity<ApiResponse<Void>> logoutAll(
            Authentication authentication,
            HttpServletRequest servletRequest
    ) {
        UUID userId = UUID.fromString(authentication.getName());
        UserAccount account = userRepository.findByIdAndDeletedFalse(userId)
                .orElseThrow(() -> new BadCredentialsException("Invalid credentials or account unavailable"));

        authorizationRevocationService.revokeAllForUser(account);
        channelAuthenticationService.revokeWhatsappAuthentications(
                account,
                sourceIp(servletRequest),
                userAgent(servletRequest)
        );
        auditLogService.record(
                AuditEventType.LOGOUT_ALL,
                account.getId(),
                account.getEmail(),
                sourceIp(servletRequest),
                userAgent(servletRequest),
                "All OAuth2 authorizations revoked"
        );

        return ResponseEntity.ok(ApiResponse.success("Logged out from all devices", null));
    }

    private UserAccount resolveUser(LogoutUserRequest request) {
        UserAccount account = null;
        if (hasText(request.email())) {
            String email = normalizeEmail(request.email());
            account = userRepository.findByEmailIgnoreCaseAndDeletedFalse(email)
                    .orElseThrow(() -> new ResourceNotFoundException("User not found"));
        }

        if (hasText(request.phoneNumber())) {
            String phoneNumber = PhoneNumberNormalizer.normalize(request.phoneNumber());
            UserAccount phoneAccount = userRepository.findByPhoneNumberAndDeletedFalse(phoneNumber)
                    .or(() -> userRepository.findByNormalizedPhoneNumberAndDeletedFalse(phoneNumber))
                    .orElseThrow(() -> new ResourceNotFoundException("User not found"));

            if (account != null && !account.getId().equals(phoneAccount.getId())) {
                throw new IllegalArgumentException("email and phoneNumber identify different users");
            }

            account = phoneAccount;
        }

        if (account == null) {
            throw new IllegalArgumentException("email or phoneNumber is required");
        }

        return account;
    }

    private String normalizeEmail(String email) {
        return email.trim().toLowerCase(Locale.ROOT);
    }

    private boolean hasText(String value) {
        return value != null && !value.isBlank();
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
