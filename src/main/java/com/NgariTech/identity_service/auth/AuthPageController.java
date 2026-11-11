package com.NgariTech.identity_service.auth;

import com.NgariTech.identity_service.auth.dto.RegisterPageRequest;
import com.NgariTech.identity_service.auth.google.GoogleLoginSession;
import com.NgariTech.identity_service.common.exception.DuplicateResourceException;
import com.NgariTech.identity_service.user.UserService;
import com.NgariTech.identity_service.user.dto.RegisterUserRequest;
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
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

@Controller
@RequiredArgsConstructor
public class AuthPageController {

    private static final String GOOGLE_AUTHORIZATION_URL = "/oauth2/authorization/google";
    private static final String CHANNEL_CONTINUE_URL = "/api/v1/auth/channel/continue#register";

    private final UserService userService;
    private final LoginVerificationService loginVerificationService;

    @GetMapping("/login")
    public String login(HttpServletRequest servletRequest, Model model) {
        addAuthPageModel(model, hasWhatsappContext(servletRequest.getSession(false)));
        return "auth/login";
    }

    @PostMapping("/login")
    public String login(
            @RequestParam("username") String username,
            @RequestParam("password") String password,
            HttpServletRequest servletRequest
    ) {
        try {
            loginVerificationService.startPasswordLogin(username, password, servletRequest);
            return "redirect:/login/verify";
        }
        catch (AuthenticationException exception) {
            return "redirect:/login?error";
        }
    }

    @GetMapping("/login/verify")
    public String verifyLogin(HttpServletRequest servletRequest, Model model) {
        LoginVerificationService.PendingLogin pendingLogin = loginVerificationService.pendingLogin(servletRequest.getSession(false));
        if (pendingLogin == null) {
            return "redirect:/login";
        }

        model.addAttribute("maskedEmail", pendingLogin.maskedEmail());
        addAuthPageModel(model, hasWhatsappContext(servletRequest.getSession(false)));
        return "auth/login-verification";
    }

    @PostMapping("/login/verify")
    public String verifyLogin(
            @RequestParam("code") String code,
            HttpServletRequest servletRequest,
            HttpServletResponse servletResponse,
            Model model
    ) {
        try {
            String redirectUrl = loginVerificationService.completeLogin(code, servletRequest, servletResponse);
            return "redirect:" + redirectUrl;
        }
        catch (AuthenticationException exception) {
            LoginVerificationService.PendingLogin pendingLogin = loginVerificationService.pendingLogin(servletRequest.getSession(false));
            if (pendingLogin == null) {
                return "redirect:/login?error";
            }

            model.addAttribute("maskedEmail", pendingLogin.maskedEmail());
            model.addAttribute("error", "The verification code is invalid or expired.");
            addAuthPageModel(model, hasWhatsappContext(servletRequest.getSession(false)));
            return "auth/login-verification";
        }
    }

    @GetMapping("/login/success")
    public String loginSuccess() {
        return "auth/login-success";
    }

    @GetMapping("/register")
    public String register(HttpServletRequest servletRequest, Model model) {
        if (hasWhatsappContext(servletRequest.getSession(false))) {
            return "redirect:" + CHANNEL_CONTINUE_URL;
        }

        if (!model.containsAttribute("registerRequest")) {
            model.addAttribute("registerRequest", RegisterPageRequest.empty());
        }
        addAuthPageModel(model, false);
        return "auth/register";
    }

    @PostMapping("/register")
    public String register(
            @Valid @ModelAttribute("registerRequest") RegisterPageRequest request,
            BindingResult bindingResult,
            HttpServletRequest servletRequest,
            Model model,
            RedirectAttributes redirectAttributes
    ) {
        if (hasWhatsappContext(servletRequest.getSession(false))) {
            return "redirect:" + CHANNEL_CONTINUE_URL;
        }

        if (!passwordsMatch(request)) {
            bindingResult.rejectValue("confirmPassword", "password.mismatch", "Passwords must match");
        }

        if (bindingResult.hasErrors()) {
            model.addAttribute("error", "Check the registration details.");
            addAuthPageModel(model, false);
            return "auth/register";
        }

        try {
            userService.register(new RegisterUserRequest(
                    request.firstName(),
                    request.lastName(),
                    request.email(),
                    request.password(),
                    request.phoneNumber()
            ));
            redirectAttributes.addAttribute("registered", "true");
            return "redirect:/login";
        }
        catch (DuplicateResourceException exception) {
            model.addAttribute("error", "Account could not be created.");
            addAuthPageModel(model, false);
            return "auth/register";
        }
    }

    private void addAuthPageModel(Model model, boolean whatsappContext) {
        model.addAttribute("whatsappContext", whatsappContext);
        model.addAttribute("googleHref", GOOGLE_AUTHORIZATION_URL);
        model.addAttribute("registerHref", whatsappContext ? CHANNEL_CONTINUE_URL : "/register");
        model.addAttribute("loginHref", "/login");
    }

    private boolean passwordsMatch(RegisterPageRequest request) {
        return request.password() != null && request.password().equals(request.confirmPassword());
    }

    private boolean hasWhatsappContext(HttpSession session) {
        return session != null && session.getAttribute(GoogleLoginSession.CHANNEL_LINK_CHALLENGE_ID) != null;
    }
}
