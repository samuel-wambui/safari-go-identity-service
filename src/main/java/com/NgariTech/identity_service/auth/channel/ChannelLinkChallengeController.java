package com.NgariTech.identity_service.auth.channel;

import com.NgariTech.identity_service.auth.channel.dto.CreateChannelLinkChallengeRequest;
import com.NgariTech.identity_service.auth.channel.dto.CreateChannelLinkChallengeResponse;
import com.NgariTech.identity_service.common.api.ApiResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/whatsapp/auth")
@RequiredArgsConstructor
public class ChannelLinkChallengeController {

    private static final Logger log = LoggerFactory.getLogger(ChannelLinkChallengeController.class);

    private final ChannelLinkChallengeService channelLinkChallengeService;

    @PostMapping("/challenges")
    public ResponseEntity<ApiResponse<CreateChannelLinkChallengeResponse>> createChallenge(
            @Valid @RequestBody CreateChannelLinkChallengeRequest request,
            Authentication authentication,
            HttpServletRequest servletRequest
    ) {
        String authenticatedClientId = authentication == null ? null : authentication.getName();
        String sourceIp = sourceIp(servletRequest);
        String userAgent = userAgent(servletRequest);
        String requestBaseUrl = requestBaseUrl(servletRequest);

        log.info(
                "Creating WhatsApp Google authentication challenge: clientId={}, sourceIp={}, requestBaseUrl={}, loginUrlPresent={}, userAgentPresent={}",
                authenticatedClientId,
                sourceIp,
                requestBaseUrl,
                request.loginUrl() != null && !request.loginUrl().isBlank(),
                userAgent != null && !userAgent.isBlank()
        );

        CreateChannelLinkChallengeResponse response = channelLinkChallengeService.createWhatsappChallenge(
                request,
                authenticatedClientId,
                sourceIp,
                userAgent,
                requestBaseUrl
        );

        return ResponseEntity.ok(ApiResponse.success("WhatsApp Google authentication link created", response));
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

    private String requestBaseUrl(HttpServletRequest request) {
        String forwarded = firstHeaderValue(request.getHeader("Forwarded"));
        String forwardedHost = forwardedParameter(forwarded, "host");
        String xForwardedHost = firstHeaderValue(request.getHeader("X-Forwarded-Host"));
        String serverHost = requestServerHost(request);
        String hostHeader = request.getHeader("Host");
        String host = firstNonBlank(
                forwardedHost,
                xForwardedHost,
                serverHost,
                hostHeader
        );
        if (host == null) {
            log.warn(
                    "Could not resolve WhatsApp challenge request base URL host: forwardedHost={}, xForwardedHost={}, serverHost={}, hostHeader={}",
                    forwardedHost,
                    xForwardedHost,
                    serverHost,
                    hostHeader
            );
            return null;
        }

        String forwardedProto = forwardedParameter(forwarded, "proto");
        String xForwardedProto = firstHeaderValue(request.getHeader("X-Forwarded-Proto"));
        String requestScheme = request.getScheme();
        String rawScheme = firstNonBlank(
                forwardedProto,
                xForwardedProto,
                requestScheme
        );
        String scheme = rawScheme;
        scheme = ("http".equalsIgnoreCase(scheme) || "https".equalsIgnoreCase(scheme))
                ? scheme.toLowerCase()
                : requestScheme;

        String forwardedPort = firstHeaderValue(request.getHeader("X-Forwarded-Port"));
        boolean forwardedPortApplied = forwardedPort != null && !hasPort(host) && !isDefaultPort(scheme, forwardedPort);
        if (forwardedPortApplied) {
            host = host + ":" + forwardedPort;
        }

        String baseUrl = scheme + "://" + host;
        log.info(
                "Resolved WhatsApp challenge request base URL: baseUrl={}, host={}, scheme={}, rawScheme={}, forwardedHost={}, xForwardedHost={}, serverHost={}, hostHeader={}, forwardedPort={}, forwardedPortApplied={}",
                baseUrl,
                host,
                scheme,
                rawScheme,
                forwardedHost,
                xForwardedHost,
                serverHost,
                hostHeader,
                forwardedPort,
                forwardedPortApplied
        );

        return baseUrl;
    }

    private String requestServerHost(HttpServletRequest request) {
        String serverName = request.getServerName();
        if (serverName == null || serverName.isBlank()) {
            return null;
        }

        int port = request.getServerPort();
        if (port > 0 && !hasPort(serverName) && !isDefaultPort(request.getScheme(), Integer.toString(port))) {
            return serverName + ":" + port;
        }

        return serverName;
    }

    private String forwardedParameter(String forwarded, String name) {
        if (forwarded == null) {
            return null;
        }

        for (String part : forwarded.split(";")) {
            String[] pair = part.trim().split("=", 2);
            if (pair.length == 2 && pair[0].trim().equalsIgnoreCase(name)) {
                return unquote(pair[1].trim());
            }
        }

        return null;
    }

    private String firstHeaderValue(String value) {
        if (value == null || value.isBlank()) {
            return null;
        }

        return value.split(",")[0].trim();
    }

    private String firstNonBlank(String... values) {
        for (String value : values) {
            if (value != null && !value.isBlank()) {
                return value.trim();
            }
        }

        return null;
    }

    private String unquote(String value) {
        if (value.length() >= 2 && value.startsWith("\"") && value.endsWith("\"")) {
            return value.substring(1, value.length() - 1);
        }

        return value;
    }

    private boolean hasPort(String host) {
        if (host.startsWith("[")) {
            return host.contains("]:");
        }

        return host.indexOf(':') >= 0;
    }

    private boolean isDefaultPort(String scheme, String port) {
        return ("http".equals(scheme) && "80".equals(port)) || ("https".equals(scheme) && "443".equals(port));
    }
}
