package com.NgariTech.identity_service.auth.channel;

import com.NgariTech.identity_service.auth.AuditEventType;
import com.NgariTech.identity_service.auth.AuditLogService;
import com.NgariTech.identity_service.auth.channel.dto.CreateChannelLinkChallengeRequest;
import com.NgariTech.identity_service.auth.channel.dto.CreateChannelLinkChallengeResponse;
import com.NgariTech.identity_service.user.PhoneNumberNormalizer;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
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
import java.util.Optional;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class ChannelLinkChallengeService {

    private static final Logger log = LoggerFactory.getLogger(ChannelLinkChallengeService.class);
    private static final String HASH_PREFIX = "sha256:";
    private static final int TOKEN_BYTES = 32;

    private final ChannelLinkChallengeRepository challengeRepository;
    private final AuditLogService auditLogService;
    private final SecureRandom secureRandom = new SecureRandom();

    @Value("${iam.google.link-token-minutes:10}")
    private long linkTokenMinutes;

    @Value("${iam.public-base-url:http://localhost:8081}")
    private String publicBaseUrl;

    @Transactional
    public CreateChannelLinkChallengeResponse createWhatsappChallenge(
            CreateChannelLinkChallengeRequest request,
            String authenticatedClientId,
            String sourceIp,
            String userAgent
    ) {
        return createWhatsappChallenge(request, authenticatedClientId, sourceIp, userAgent, null);
    }

    @Transactional
    public CreateChannelLinkChallengeResponse createWhatsappChallenge(
            CreateChannelLinkChallengeRequest request,
            String authenticatedClientId,
            String sourceIp,
            String userAgent,
            String requestBaseUrl
    ) {
        String rawToken = newToken();
        String phoneNumber = PhoneNumberNormalizer.normalize(request.phoneNumber());
        Instant expiresAt = Instant.now().plus(Duration.ofMinutes(linkTokenMinutes));

        ChannelLinkChallenge challenge = new ChannelLinkChallenge();
        challenge.setChannel(ChannelLinkChannel.WHATSAPP);
        challenge.setPhoneNumber(phoneNumber);
        challenge.setTokenHash(hash(rawToken));
        challenge.setExpiresAt(expiresAt);
        challenge.setRequestingClientId(request.requestingClientId() == null || request.requestingClientId().isBlank()
                ? authenticatedClientId
                : request.requestingClientId().trim());

        challengeRepository.save(challenge);
        auditLogService.record(
                AuditEventType.CHANNEL_LINK_CHALLENGE_CREATED,
                null,
                null,
                sourceIp,
                userAgent,
                "WhatsApp Google link challenge created for client " + authenticatedClientId
        );

        String channelBaseUrl = selectedBaseUrl(request.loginUrl(), requestBaseUrl);
        return new CreateChannelLinkChallengeResponse(
                channelUrl(rawToken, "register", channelBaseUrl),
                channelUrl(rawToken, "login", channelBaseUrl),
                expiresAt
        );
    }

    @Transactional
    public Optional<UUID> resolveForStart(String rawToken, String sourceIp, String userAgent) {
        if (rawToken == null || rawToken.isBlank()) {
            return Optional.empty();
        }

        Optional<ChannelLinkChallenge> challenge = challengeRepository.findByTokenHash(hash(rawToken.trim()));
        if (challenge.isEmpty()) {
            return Optional.empty();
        }

        ChannelLinkChallenge value = challenge.get();
        if (isExpired(value)) {
            value.setStatus(ChannelLinkChallengeStatus.EXPIRED);
            auditLogService.record(
                    AuditEventType.CHANNEL_LINK_CHALLENGE_EXPIRED,
                    null,
                    null,
                    sourceIp,
                    userAgent,
                    "Expired WhatsApp Google link challenge was opened"
            );
            return Optional.empty();
        }

        if (value.getConsumedAt() != null || value.getStatus() != ChannelLinkChallengeStatus.ACTIVE) {
            auditLogService.record(
                    AuditEventType.CHANNEL_LINK_CHALLENGE_REUSED,
                    null,
                    null,
                    sourceIp,
                    userAgent,
                    "Consumed WhatsApp Google link challenge was reused"
            );
            return Optional.empty();
        }

        return Optional.of(value.getId());
    }

    @Transactional
    public ChannelLinkChallenge requireUsableForUpdate(UUID challengeId, String sourceIp, String userAgent) {
        ChannelLinkChallenge challenge = challengeRepository.findByIdForUpdate(challengeId)
                .orElseThrow(() -> new ChannelLinkChallengeException("Invalid channel link challenge"));

        if (isExpired(challenge)) {
            challenge.setStatus(ChannelLinkChallengeStatus.EXPIRED);
            auditLogService.record(
                    AuditEventType.CHANNEL_LINK_CHALLENGE_EXPIRED,
                    null,
                    null,
                    sourceIp,
                    userAgent,
                    "Expired WhatsApp Google link challenge was used"
            );
            throw new ChannelLinkChallengeException("Invalid channel link challenge");
        }

        if (challenge.getConsumedAt() != null || challenge.getStatus() != ChannelLinkChallengeStatus.ACTIVE) {
            auditLogService.record(
                    AuditEventType.CHANNEL_LINK_CHALLENGE_REUSED,
                    null,
                    null,
                    sourceIp,
                    userAgent,
                    "Consumed WhatsApp Google link challenge was reused"
            );
            throw new ChannelLinkChallengeException("Invalid channel link challenge");
        }

        return challenge;
    }

    @Transactional(readOnly = true)
    public ChannelLinkChallenge requireUsable(UUID challengeId, String sourceIp, String userAgent) {
        ChannelLinkChallenge challenge = challengeRepository.findById(challengeId)
                .orElseThrow(() -> new ChannelLinkChallengeException("Invalid channel link challenge"));

        if (isExpired(challenge)) {
            auditLogService.record(
                    AuditEventType.CHANNEL_LINK_CHALLENGE_EXPIRED,
                    null,
                    null,
                    sourceIp,
                    userAgent,
                    "Expired WhatsApp channel link challenge was opened"
            );
            throw new ChannelLinkChallengeException("Invalid channel link challenge");
        }

        if (challenge.getConsumedAt() != null || challenge.getStatus() != ChannelLinkChallengeStatus.ACTIVE) {
            auditLogService.record(
                    AuditEventType.CHANNEL_LINK_CHALLENGE_REUSED,
                    null,
                    null,
                    sourceIp,
                    userAgent,
                    "Consumed WhatsApp channel link challenge was opened"
            );
            throw new ChannelLinkChallengeException("Invalid channel link challenge");
        }

        return challenge;
    }

    public void consumeLoaded(ChannelLinkChallenge challenge) {
        challenge.setStatus(ChannelLinkChallengeStatus.CONSUMED);
        challenge.setConsumedAt(Instant.now());
    }

    private boolean isExpired(ChannelLinkChallenge challenge) {
        return challenge.getExpiresAt() == null || !Instant.now().isBefore(challenge.getExpiresAt());
    }

    private String channelUrl(String rawToken, String authMode, String baseUrl) {
        return UriComponentsBuilder.fromUriString(baseUrl)
                .path("/api/v1/auth/channel/start")
                .queryParam("linkToken", rawToken)
                .queryParam("authMode", authMode)
                .build()
                .toUriString();
    }

    private String selectedBaseUrl(String loginUrl, String requestBaseUrl) {
        Optional<String> configuredPublicBaseUrl = normalizedConfiguredPublicBaseUrl();
        if (configuredPublicBaseUrl.isPresent()) {
            log.info(
                    "Using configured identity-service public base URL for WhatsApp challenge: baseUrl={}, requestBaseUrl={}",
                    configuredPublicBaseUrl.get(),
                    requestBaseUrl
            );
            return configuredPublicBaseUrl.get();
        }

        Optional<String> loginUrlBaseUrl = normalizedLoginUrlBaseUrl(loginUrl);
        if (loginUrlBaseUrl.isPresent()) {
            log.info(
                    "Using WhatsApp challenge base URL from loginUrl domain: baseUrl={}, requestBaseUrl={}",
                    loginUrlBaseUrl.get(),
                    requestBaseUrl
            );
            return loginUrlBaseUrl.get();
        }

        Optional<String> requestUrlBaseUrl = normalizedRequestBaseUrl(requestBaseUrl);
        if (requestUrlBaseUrl.isPresent()) {
            log.info("Using WhatsApp challenge base URL from request host: baseUrl={}", requestUrlBaseUrl.get());
            return requestUrlBaseUrl.get();
        }

        String fallbackBaseUrl = normalizedBaseUrl(publicBaseUrl).orElseThrow();
        log.info("Using WhatsApp challenge base URL from configured public base URL: baseUrl={}", fallbackBaseUrl);
        return fallbackBaseUrl;
    }

    private Optional<String> normalizedConfiguredPublicBaseUrl() {
        return normalizedBaseUrl(publicBaseUrl)
                .filter(baseUrl -> !isLocalBaseUrl(baseUrl));
    }

    private Optional<String> normalizedLoginUrlBaseUrl(String value) {
        return normalizedUrlDomain(value)
                .filter(baseUrl -> !isLocalBaseUrl(baseUrl));
    }

    private Optional<String> normalizedUrlDomain(String value) {
        if (value == null || value.isBlank()) {
            return Optional.empty();
        }

        try {
            URI uri = new URI(value.trim());
            String scheme = uri.getScheme();
            String host = uri.getHost();
            if (scheme == null || host == null || host.isBlank()) {
                return Optional.empty();
            }
            if (!"http".equalsIgnoreCase(scheme) && !"https".equalsIgnoreCase(scheme)) {
                return Optional.empty();
            }

            UriComponentsBuilder builder = UriComponentsBuilder.newInstance()
                    .scheme(scheme.toLowerCase())
                    .host(host);
            if (uri.getPort() > 0) {
                builder.port(uri.getPort());
            }
            return Optional.of(builder.build().toUriString());
        }
        catch (URISyntaxException exception) {
            return Optional.empty();
        }
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
        String normalizedHost = host.trim().toLowerCase();
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
