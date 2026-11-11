package com.NgariTech.identity_service.auth;

import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.time.Instant;
import java.util.Locale;
import java.util.concurrent.ConcurrentHashMap;

@Component
public class AuthenticationRateLimiter {

    private static final int MAX_EMAIL_ATTEMPTS = 10;
    private static final int MAX_IP_ATTEMPTS = 50;
    private static final Duration WINDOW = Duration.ofMinutes(15);
    private static final String GENERIC_ERROR = "Invalid credentials or account unavailable";

    private final ConcurrentHashMap<String, AttemptWindow> attempts = new ConcurrentHashMap<>();

    public void checkAllowed(String email, String sourceIp) {
        if (!isAllowed(email, sourceIp)) {
            throw new BadCredentialsException(GENERIC_ERROR);
        }
    }

    public boolean isAllowed(String email, String sourceIp) {
        return currentCount(emailKey(email)) < MAX_EMAIL_ATTEMPTS
                && currentCount(ipKey(sourceIp)) < MAX_IP_ATTEMPTS;
    }

    public void recordFailure(String email, String sourceIp) {
        increment(emailKey(email));
        increment(ipKey(sourceIp));
    }

    public void recordSuccess(String email) {
        attempts.remove(emailKey(email));
    }

    private int currentCount(String key) {
        AttemptWindow window = attempts.get(key);
        if (window == null || window.isExpired()) {
            attempts.remove(key);
            return 0;
        }

        return window.count();
    }

    private void increment(String key) {
        attempts.compute(key, (ignored, existing) -> {
            if (existing == null || existing.isExpired()) {
                return new AttemptWindow(Instant.now().plus(WINDOW), 1);
            }

            return new AttemptWindow(existing.expiresAt(), existing.count() + 1);
        });
    }

    private String emailKey(String email) {
        return "email:" + email.trim().toLowerCase(Locale.ROOT);
    }

    private String ipKey(String sourceIp) {
        return "ip:" + (sourceIp == null || sourceIp.isBlank() ? "unknown" : sourceIp.trim());
    }

    private record AttemptWindow(Instant expiresAt, int count) {

        private boolean isExpired() {
            return !Instant.now().isBefore(expiresAt);
        }
    }
}
