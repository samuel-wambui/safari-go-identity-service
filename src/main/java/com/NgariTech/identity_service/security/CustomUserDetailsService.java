package com.NgariTech.identity_service.security;

import com.NgariTech.identity_service.auth.AuthenticationRateLimiter;
import com.NgariTech.identity_service.auth.LoginAttemptService;
import com.NgariTech.identity_service.user.UserAccount;
import com.NgariTech.identity_service.user.UserRepository;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

@Service
@RequiredArgsConstructor
public class CustomUserDetailsService implements UserDetailsService {

    private final UserRepository userRepository;
    private final LoginAttemptService loginAttemptService;
    private final AuthenticationRateLimiter authenticationRateLimiter;
    private final IamUserPrincipalService iamUserPrincipalService;

    @Override
    @Transactional(readOnly = true)
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        if (email == null || email.isBlank()) {
            throw new UsernameNotFoundException("Invalid credentials");
        }

        String normalizedEmail = email.trim();
        String sourceIp = sourceIp();
        String userAgent = userAgent();

        if (!authenticationRateLimiter.isAllowed(normalizedEmail, sourceIp)) {
            loginAttemptService.recordRateLimitFailure(normalizedEmail, sourceIp, userAgent);
            throw new LockedException("Invalid credentials");
        }

        loginAttemptService.unlockIfExpired(normalizedEmail, sourceIp, userAgent);

        UserAccount account = userRepository
                .findByEmailIgnoreCaseAndDeletedFalse(normalizedEmail)
                .orElseThrow(() -> new UsernameNotFoundException("Invalid credentials"));

        if (!account.isPasswordLoginEnabled()) {
            throw new UsernameNotFoundException("Invalid credentials");
        }

        return iamUserPrincipalService.userDetails(account);
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
