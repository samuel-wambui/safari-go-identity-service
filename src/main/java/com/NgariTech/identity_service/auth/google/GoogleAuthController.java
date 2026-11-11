package com.NgariTech.identity_service.auth.google;

import com.NgariTech.identity_service.auth.channel.ChannelLinkChallengeService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.io.IOException;
import java.util.Optional;
import java.util.UUID;

@Controller
@RequestMapping("/api/v1/auth/google")
@RequiredArgsConstructor
public class GoogleAuthController {

    private final ChannelLinkChallengeService channelLinkChallengeService;

    @GetMapping("/start")
    public void start(
            @RequestParam("linkToken") String linkToken,
            HttpServletRequest request,
            HttpServletResponse response
    ) throws IOException {
        Optional<UUID> challengeId = channelLinkChallengeService.resolveForStart(
                linkToken,
                sourceIp(request),
                request.getHeader("User-Agent")
        );

        if (challengeId.isEmpty()) {
            response.sendRedirect("/api/v1/auth/google/failure");
            return;
        }

        HttpSession session = request.getSession(true);
        session.setAttribute(GoogleLoginSession.CHANNEL_LINK_CHALLENGE_ID, challengeId.get());
        response.sendRedirect("/oauth2/authorization/google");
    }

    @GetMapping("/success")
    public String success() {
        return "redirect:/api/v1/auth/channel/success";
    }

    @GetMapping("/failure")
    public String failure() {
        return "redirect:/api/v1/auth/channel/failure";
    }

    private String sourceIp(HttpServletRequest request) {
        String forwardedFor = request.getHeader("X-Forwarded-For");
        if (forwardedFor != null && !forwardedFor.isBlank()) {
            return forwardedFor.split(",")[0].trim();
        }

        return request.getRemoteAddr();
    }
}
