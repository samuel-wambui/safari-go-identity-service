package com.NgariTech.identity_service.auth;

import com.NgariTech.identity_service.auth.dto.ForgotPasswordRequest;
import com.NgariTech.identity_service.auth.dto.ResetPasswordRequest;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
@RequiredArgsConstructor
public class PasswordResetPageController {

    private static final Logger log = LoggerFactory.getLogger(PasswordResetPageController.class);

    private final PasswordResetService passwordResetService;

    @GetMapping("/forgot-password")
    public String forgotPassword(Model model) {
        if (!model.containsAttribute("forgotPasswordRequest")) {
            model.addAttribute("forgotPasswordRequest", ForgotPasswordRequest.empty());
        }
        return "auth/forgot-password";
    }

    @PostMapping("/forgot-password")
    public String forgotPassword(
            @Valid @ModelAttribute("forgotPasswordRequest") ForgotPasswordRequest request,
            BindingResult bindingResult,
            HttpServletRequest servletRequest,
            Model model
    ) {
        if (bindingResult.hasErrors()) {
            model.addAttribute("error", "Enter a valid email address.");
            return "auth/forgot-password";
        }

        String sourceIp = sourceIp(servletRequest);
        String userAgent = userAgent(servletRequest);
        String requestBaseUrl = requestBaseUrl(servletRequest);

        log.info(
                "Requesting password reset link: sourceIp={}, requestBaseUrl={}, userAgentPresent={}",
                sourceIp,
                requestBaseUrl,
                userAgent != null && !userAgent.isBlank()
        );

        passwordResetService.requestReset(request.email(), sourceIp, userAgent, requestBaseUrl);
        return "redirect:/forgot-password?sent=true";
    }

    @GetMapping("/reset-password")
    public String resetPassword(@RequestParam(name = "token", required = false) String token, Model model) {
        boolean tokenUsable = passwordResetService.isTokenUsable(token);
        model.addAttribute("tokenUsable", tokenUsable);
        model.addAttribute("resetPasswordRequest", ResetPasswordRequest.forToken(token == null ? "" : token));
        if (!tokenUsable) {
            model.addAttribute("error", "This reset link is invalid or expired.");
        }
        return "auth/reset-password";
    }

    @PostMapping("/reset-password")
    public String resetPassword(
            @Valid @ModelAttribute("resetPasswordRequest") ResetPasswordRequest request,
            BindingResult bindingResult,
            HttpServletRequest servletRequest,
            Model model
    ) {
        boolean tokenUsable = passwordResetService.isTokenUsable(request.token());
        model.addAttribute("tokenUsable", tokenUsable);

        if (!passwordsMatch(request)) {
            bindingResult.rejectValue("confirmPassword", "password.mismatch", "Passwords must match");
        }

        if (!tokenUsable) {
            model.addAttribute("error", "This reset link is invalid or expired.");
            return "auth/reset-password";
        }

        if (bindingResult.hasErrors()) {
            model.addAttribute("error", "Check the password details.");
            return "auth/reset-password";
        }

        try {
            passwordResetService.resetPassword(request, sourceIp(servletRequest), userAgent(servletRequest));
            return "redirect:/login?reset=true";
        }
        catch (BadCredentialsException exception) {
            model.addAttribute("tokenUsable", false);
            model.addAttribute("error", "This reset link is invalid or expired.");
            return "auth/reset-password";
        }
    }

    private boolean passwordsMatch(ResetPasswordRequest request) {
        return request.password() != null && request.password().equals(request.confirmPassword());
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
                    "Could not resolve password reset request base URL host: forwardedHost={}, xForwardedHost={}, serverHost={}, hostHeader={}",
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
                "Resolved password reset request base URL: baseUrl={}, host={}, scheme={}, rawScheme={}, forwardedHost={}, xForwardedHost={}, serverHost={}, hostHeader={}, forwardedPort={}, forwardedPortApplied={}",
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
