package com.NgariTech.identity_service.auth.channel;

import com.NgariTech.identity_service.auth.channel.dto.ChannelLocalLoginRequest;
import com.NgariTech.identity_service.auth.channel.dto.ChannelLocalRegisterRequest;
import com.NgariTech.identity_service.auth.google.GoogleLoginSession;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.AuthenticationException;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.util.Optional;
import java.util.UUID;

@Controller
@RequestMapping("/api/v1/auth/channel")
@RequiredArgsConstructor
public class ChannelAuthPageController {

    private static final String CHANNEL_CONTINUE_PATH = "/api/v1/auth/channel/continue";
    private static final String GENERIC_ERROR = "Authentication could not be completed. Return to WhatsApp and request a new link.";
    private static final String REGISTER_AUTH_MODE = "register";

    private final ChannelLinkChallengeService channelLinkChallengeService;
    private final ChannelLocalAuthenticationService channelLocalAuthenticationService;

    @GetMapping("/start")
    public String start(
            @RequestParam("linkToken") String linkToken,
            @RequestParam(value = "authMode", required = false) String authMode,
            HttpServletRequest request
    ) {
        Optional<UUID> challengeId = channelLinkChallengeService.resolveForStart(
                linkToken,
                sourceIp(request),
                request.getHeader("User-Agent")
        );

        if (challengeId.isEmpty()) {
            return "redirect:/api/v1/auth/channel/failure";
        }

        request.getSession(true).setAttribute(GoogleLoginSession.CHANNEL_LINK_CHALLENGE_ID, challengeId.get());
        return "redirect:" + channelContinuePath(authMode);
    }

    @GetMapping("/continue")
    public String continuePage(HttpServletRequest request, Model model) {
        UUID challengeId = challengeId(request.getSession(false));
        if (challengeId == null) {
            return "redirect:/api/v1/auth/channel/failure";
        }

        try {
            ChannelLinkChallenge challenge = channelLinkChallengeService.requireUsable(
                    challengeId,
                    sourceIp(request),
                    request.getHeader("User-Agent")
            );
            model.addAttribute("loginRequest", new ChannelLocalLoginRequest("", ""));
            model.addAttribute("registerRequest", ChannelLocalRegisterRequest.empty());
            model.addAttribute("expiresAt", challenge.getExpiresAt());
            addChannelModel(model, "login");
            return "auth/channel/continue";
        }
        catch (ChannelLinkChallengeException exception) {
            return "redirect:/api/v1/auth/channel/failure";
        }
    }

    @PostMapping("/login")
    public String login(
            @Valid @ModelAttribute("loginRequest") ChannelLocalLoginRequest loginRequest,
            BindingResult bindingResult,
            HttpServletRequest request,
            HttpServletResponse response,
            Model model
    ) {
        UUID challengeId = challengeId(request.getSession(false));
        if (challengeId == null) {
            return "redirect:/api/v1/auth/channel/failure";
        }

        if (bindingResult.hasErrors()) {
            return formError(model, "Check your email and password.", "login");
        }

        try {
            channelLocalAuthenticationService.login(challengeId, loginRequest, request, response);
            clearChallenge(request.getSession(false));
            return "redirect:/api/v1/auth/channel/success";
        }
        catch (AuthenticationException | ChannelLinkChallengeException exception) {
            return formError(model, "Invalid credentials or account unavailable.", "login");
        }
    }

    @PostMapping("/register")
    public String register(
            @Valid @ModelAttribute("registerRequest") ChannelLocalRegisterRequest registerRequest,
            BindingResult bindingResult,
            HttpServletRequest request,
            HttpServletResponse response,
            Model model
    ) {
        UUID challengeId = challengeId(request.getSession(false));
        if (challengeId == null) {
            return "redirect:/api/v1/auth/channel/failure";
        }

        if (!passwordsMatch(registerRequest)) {
            bindingResult.rejectValue("confirmPassword", "password.mismatch", "Passwords must match");
        }

        if (bindingResult.hasErrors()) {
            return formError(model, "Check the registration details.", "register");
        }

        try {
            channelLocalAuthenticationService.register(challengeId, registerRequest, request, response);
            clearChallenge(request.getSession(false));
            return "redirect:/api/v1/auth/channel/success";
        }
        catch (RuntimeException exception) {
            return formError(model, "Account could not be created or linked.", "register");
        }
    }

    @GetMapping("/success")
    public String success() {
        return "auth/channel/success";
    }

    @GetMapping("/failure")
    public String failure(Model model) {
        model.addAttribute("message", GENERIC_ERROR);
        return "auth/channel/failure";
    }

    private String formError(Model model, String message, String authMode) {
        model.addAttribute("loginRequest", new ChannelLocalLoginRequest("", ""));
        if (!model.containsAttribute("registerRequest")) {
            model.addAttribute("registerRequest", ChannelLocalRegisterRequest.empty());
        }
        model.addAttribute("error", message);
        addChannelModel(model, authMode);
        return "auth/channel/continue";
    }

    private void addChannelModel(Model model, String authMode) {
        model.addAttribute("whatsappContext", true);
        model.addAttribute("authMode", authMode);
        model.addAttribute("googleHref", "/oauth2/authorization/google");
        model.addAttribute("registerHref", "#register");
        model.addAttribute("loginHref", "#login");
    }

    private boolean passwordsMatch(ChannelLocalRegisterRequest request) {
        return request.password() != null && request.password().equals(request.confirmPassword());
    }

    private String channelContinuePath(String authMode) {
        if (REGISTER_AUTH_MODE.equalsIgnoreCase(authMode)) {
            return CHANNEL_CONTINUE_PATH + "#register";
        }

        return "/login";
    }

    private UUID challengeId(HttpSession session) {
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

    private void clearChallenge(HttpSession session) {
        if (session != null) {
            session.removeAttribute(GoogleLoginSession.CHANNEL_LINK_CHALLENGE_ID);
        }
    }

    private String sourceIp(HttpServletRequest request) {
        String forwardedFor = request.getHeader("X-Forwarded-For");
        if (forwardedFor != null && !forwardedFor.isBlank()) {
            return forwardedFor.split(",")[0].trim();
        }

        return request.getRemoteAddr();
    }
}
