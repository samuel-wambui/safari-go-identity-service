package com.NgariTech.identity_service;

import com.NgariTech.identity_service.auth.VerificationCodeGenerator;
import com.NgariTech.identity_service.email.IdentityEmailSender;
import com.NgariTech.identity_service.role.RoleNames;
import com.NgariTech.identity_service.user.UserAccount;
import com.NgariTech.identity_service.user.UserRepository;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.web.util.UriComponentsBuilder;
import tools.jackson.core.type.TypeReference;
import tools.jackson.databind.ObjectMapper;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.Base64;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.not;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest(properties = "iam.public-base-url=https://login.safarigo.test")
@AutoConfigureMockMvc
class IdentityServiceApplicationTests {

    private static final String TRAVEL_WEB_CLIENT_ID = "travel-web-bff";
    private static final String TRAVEL_WEB_CLIENT_SECRET = "travel-web-dev-secret";
    private static final String N8N_CLIENT_ID = "n8n-orchestrator";
    private static final String N8N_CLIENT_SECRET = "n8n-dev-secret";
    private static final String REDIRECT_URI = "http://127.0.0.1:8082/login/oauth2/code/iam";
    private static final String PASSWORD = "Password123!";
    private static final String LOGIN_CODE = "Aa123B";

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private JdbcTemplate jdbcTemplate;

    @Autowired
    @Qualifier("resourceServerJwtDecoder")
    private JwtDecoder jwtDecoder;

    @Autowired
    private CapturingIdentityEmailSender emailSender;

    @Test
    void loginPageLoadsWithCsrfGoogleLinkAndGenericMessages() throws Exception {
        mockMvc.perform(get("/login"))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("Welcome back")))
                .andExpect(content().string(containsString("name=\"_csrf\"")))
                .andExpect(content().string(containsString("href=\"/oauth2/authorization/google\"")))
                .andExpect(content().string(containsString("class=\"hero-route-overlay\"")))
                .andExpect(content().string(containsString("aria-hidden=\"true\" focusable=\"false\"")))
                .andExpect(content().string(containsString("Email or username")))
                .andExpect(content().string(containsString("href=\"/forgot-password\"")))
                .andExpect(content().string(not(containsString("Continuing from WhatsApp"))));

        mockMvc.perform(get("/login").param("error", ""))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("Invalid credentials or account unavailable")))
                .andExpect(content().string(not(containsString("BadCredentialsException"))));

        mockMvc.perform(get("/login").param("registered", "true"))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("Account created. Sign in to continue.")));

        mockMvc.perform(get("/login").param("reset", "true"))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("Password updated. Sign in to continue.")));
    }

    @Test
    void faviconRequestReturnsNoContentInsteadOfMissingStaticResource() throws Exception {
        mockMvc.perform(get("/favicon.ico"))
                .andExpect(status().isNoContent())
                .andExpect(content().string(""));
    }

    @Test
    void registrationPageLoadsWithCsrfAndNoPrivilegedFields() throws Exception {
        mockMvc.perform(get("/register"))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("Create your account")))
                .andExpect(content().string(containsString("name=\"_csrf\"")))
                .andExpect(content().string(containsString("name=\"firstName\"")))
                .andExpect(content().string(containsString("name=\"lastName\"")))
                .andExpect(content().string(containsString("name=\"email\"")))
                .andExpect(content().string(containsString("name=\"password\"")))
                .andExpect(content().string(containsString("name=\"confirmPassword\"")))
                .andExpect(content().string(not(containsString("name=\"role"))))
                .andExpect(content().string(not(containsString("name=\"permissions"))))
                .andExpect(content().string(not(containsString("name=\"enabled"))))
                .andExpect(content().string(not(containsString("name=\"emailVerified"))));
    }

    @Test
    void loginPageDoesNotRenderUnsafeContinuationParameters() throws Exception {
        mockMvc.perform(get("/login")
                        .param("continue", "https://evil.example/callback")
                        .param("linkToken", "should-not-render"))
                .andExpect(status().isOk())
                .andExpect(content().string(not(containsString("evil.example"))))
                .andExpect(content().string(not(containsString("should-not-render"))));
    }

    @Test
    void channelResultPagesRenderGenericSafeMessages() throws Exception {
        mockMvc.perform(get("/api/v1/auth/channel/success"))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("Authentication successful")))
                .andExpect(content().string(containsString("return to WhatsApp")))
                .andExpect(content().string(not(containsString("linkToken"))))
                .andExpect(content().string(not(containsString("access_token"))));

        mockMvc.perform(get("/api/v1/auth/channel/failure"))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("We couldn't complete authentication")))
                .andExpect(content().string(containsString("request a new secure link")))
                .andExpect(content().string(not(containsString("linkToken"))))
                .andExpect(content().string(not(containsString("access_token"))));
    }

    @Test
    void oauth2AuthorizationFlowStillReachesCustomLoginPage() throws Exception {
        Pkce pkce = pkce();

        mockMvc.perform(get(authorizationUri(pkce)).accept(MediaType.TEXT_HTML))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/login"));
    }

    @Test
    void publicRegistrationPageCreatesTravellerThenRedirectsToLogin() throws Exception {
        String email = uniqueEmail("page-register");

        mockMvc.perform(post("/register")
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .param("firstName", "Page")
                        .param("lastName", "Traveller")
                        .param("email", email)
                        .param("phoneNumber", uniquePhone())
                        .param("password", PASSWORD)
                        .param("confirmPassword", PASSWORD))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/login?registered=true"));

        UserAccount account = userRepository.findByEmailIgnoreCaseAndDeletedFalse(email).orElseThrow();
        assertThat(account.getRoleId()).isEqualTo(RoleNames.TRAVELLER_ID);
    }

    @Test
    void registrationStoresHashedPasswordAndDefaultTravellerRole() throws Exception {
        String email = uniqueEmail("register");

        register(email, uniquePhone());

        UserAccount account = userRepository.findByEmailIgnoreCaseAndDeletedFalse(email).orElseThrow();
        assertThat(account.getPassword()).startsWith("{bcrypt}");
        assertThat(account.getRoleId()).isEqualTo(RoleNames.TRAVELLER_ID);
        assertThat(account.isEnabled()).isTrue();
        assertThat(account.isAccountNonLocked()).isTrue();
    }

    @Test
    @SuppressWarnings("unchecked")
    void registeredIamUserCanLoginToMobileWithPhonePasswordAndReceivesProfileClaims() throws Exception {
        String phoneNumber = uniquePhone();
        String email = uniqueEmail("mobile-login");
        UserAccount account = register(email, phoneNumber);

        MvcResult result = mockMvc.perform(post("/api/v1/mobile/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(Map.of(
                                "phoneNumber", phoneNumber.substring(0, 5) + " " + phoneNumber.substring(5),
                                "password", PASSWORD
                        ))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.code").value("SUCCESS"))
                .andExpect(jsonPath("$.message").value("Mobile login successful"))
                .andExpect(jsonPath("$.data.userId").value(account.getId().toString()))
                .andExpect(jsonPath("$.data.mobileSessionId").exists())
                .andExpect(jsonPath("$.data.email").value(email))
                .andExpect(jsonPath("$.data.phoneNumber").value(phoneNumber))
                .andExpect(jsonPath("$.data.firstName").value("Test"))
                .andExpect(jsonPath("$.data.lastName").value("User"))
                .andExpect(jsonPath("$.data.tokenType").value("Bearer"))
                .andExpect(jsonPath("$.data.accessToken").exists())
                .andExpect(jsonPath("$.data.expiresIn").value(86400))
                .andExpect(jsonPath("$.data.expiresAt").exists())
                .andExpect(jsonPath("$.data.refreshToken").doesNotExist())
                .andReturn();

        Map<String, Object> response = tokenResponse(result);
        Map<String, Object> data = (Map<String, Object>) response.get("data");
        Jwt mobileToken = jwtDecoder.decode((String) data.get("accessToken"));
        String mobileSessionId = (String) data.get("mobileSessionId");
        assertThat(mobileToken.getSubject()).isEqualTo(account.getId().toString());
        assertThat(mobileToken.getAudience()).contains("travel-platform-api");
        assertThat(mobileToken.getClaimAsStringList("roles")).contains("TRAVELLER");
        assertThat(mobileToken.getClaimAsStringList("permissions")).contains("travel:read", "travel:create");
        assertThat(mobileToken.getClaimAsString("client_id")).isEqualTo("safarigo-mobile");
        assertThat(mobileToken.getClaimAsString("email")).isEqualTo(email);
        assertThat(mobileToken.getClaimAsString("phone_number")).isEqualTo(phoneNumber);
        assertThat(mobileToken.getClaimAsString("given_name")).isEqualTo("Test");
        assertThat(mobileToken.getClaimAsString("family_name")).isEqualTo("User");
        assertThat(mobileToken.getClaimAsString("auth_method")).isEqualTo("MOBILE_PASSWORD");
        assertThat(mobileToken.getClaimAsString("mobile_session_id")).isEqualTo(mobileSessionId);

        Integer sessionCount = jdbcTemplate.queryForObject(
                """
                select count(*)
                from mobile_sessions
                where id = ?
                  and user_id = ?
                  and auth_method = 'MOBILE_PASSWORD'
                  and status = 'ACTIVE'
                """,
                Integer.class,
                UUID.fromString(mobileSessionId),
                account.getId()
        );
        assertThat(sessionCount).isEqualTo(1);

        mockMvc.perform(post("/api/v1/mobile/auth/logout")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + data.get("accessToken"))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.code").value("SUCCESS"))
                .andExpect(jsonPath("$.message").value("Mobile logout processed"))
                .andExpect(jsonPath("$.data.userId").value(account.getId().toString()))
                .andExpect(jsonPath("$.data.mobileSessionId").value(mobileSessionId))
                .andExpect(jsonPath("$.data.status").value("REVOKED"))
                .andExpect(jsonPath("$.data.revokedAt").exists());

        Integer revokedSessionCount = jdbcTemplate.queryForObject(
                """
                select count(*)
                from mobile_sessions
                where id = ?
                  and user_id = ?
                  and status = 'REVOKED'
                  and revoked_at is not null
                """,
                Integer.class,
                UUID.fromString(mobileSessionId),
                account.getId()
        );
        assertThat(revokedSessionCount).isEqualTo(1);
    }

    @Test
    void mobileLogoutRequiresAuthenticatedMobileToken() throws Exception {
        mockMvc.perform(post("/api/v1/mobile/auth/logout")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{}"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void mobileLoginAcceptsKenyanLocalPhoneNumberFormat() throws Exception {
        String phoneNumber = uniquePhone();
        UserAccount account = register(uniqueEmail("mobile-login-local-phone"), phoneNumber);
        String localPhoneNumber = "0" + phoneNumber.substring(3);

        mockMvc.perform(post("/api/v1/mobile/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(Map.of(
                                "phoneNumber", localPhoneNumber,
                                "password", PASSWORD
                        ))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.userId").value(account.getId().toString()))
                .andExpect(jsonPath("$.data.phoneNumber").value(phoneNumber))
                .andExpect(jsonPath("$.data.mobileSessionId").exists());
    }

    @Test
    void mobileLoginRejectsInvalidPasswordForRegisteredUser() throws Exception {
        String phoneNumber = uniquePhone();
        register(uniqueEmail("mobile-login-denied"), phoneNumber);

        mockMvc.perform(post("/api/v1/mobile/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(Map.of(
                                "phoneNumber", phoneNumber,
                                "password", "WrongPassword123!"
                        ))))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.code").value("UNAUTHORIZED"))
                .andExpect(jsonPath("$.message").value("Invalid credentials or account unavailable"));
    }

    @Test
    void correctFormLoginSucceedsAndFourIncorrectAttemptsLockAccount() throws Exception {
        String email = uniqueEmail("lock");
        register(email, uniquePhone());

        MvcResult passwordAccepted = mockMvc.perform(post("/login")
                        .with(csrf())
                        .param("username", email)
                        .param("password", PASSWORD))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/login/verify"))
                .andReturn();

        assertThat(emailSender.latestBody()).contains(LOGIN_CODE);
        MockHttpSession session = (MockHttpSession) passwordAccepted.getRequest().getSession(false);
        mockMvc.perform(post("/login/verify")
                        .with(csrf())
                        .session(session)
                        .param("code", LOGIN_CODE))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/login/success"));

        mockMvc.perform(get("/login/success").session(session))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("Login successful")))
                .andExpect(content().string(containsString("You are now authenticated.")))
                .andExpect(content().string(containsString("action=\"/logout\"")));

        mockMvc.perform(post("/logout").with(csrf()).session(session))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/login?logout"));

        for (int attempt = 0; attempt < 4; attempt++) {
            mockMvc.perform(post("/login")
                            .with(csrf())
                            .param("username", email)
                            .param("password", "wrong-password"))
                    .andExpect(status().is3xxRedirection())
                    .andExpect(redirectedUrl("/login?error"));
        }

        UserAccount account = userRepository.findByEmailIgnoreCaseAndDeletedFalse(email).orElseThrow();
        assertThat(account.isAccountNonLocked()).isFalse();
        assertThat(account.getFailedLoginAttempts()).isEqualTo(4);
        assertThat(account.getLockedAt()).isNotNull();
        assertThat(account.getLockExpiresAt()).isNotNull();
    }

    @Test
    @SuppressWarnings("unchecked")
    void whatsappLoginLinkUsesIdentityLoginFormAndCompletesWhatsappAuthentication() throws Exception {
        String phoneNumber = uniquePhone();
        String email = uniqueEmail("whatsapp-login-form");
        UserAccount account = register(email, phoneNumber);
        emailSender.clear();

        String challengeAccessToken = n8nServiceAccessToken("service:n8n channel_auth:create");
        MvcResult challengeResult = mockMvc.perform(post("/api/v1/whatsapp/auth/challenges")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + challengeAccessToken)
                        .header("X-Forwarded-Proto", "https")
                        .header("X-Forwarded-Host", "gateway.safarigo.test")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(Map.of("phoneNumber", phoneNumber))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.loginUrl").exists())
                .andReturn();

        Map<String, Object> challengeResponse = tokenResponse(challengeResult);
        Map<String, Object> challengeData = (Map<String, Object>) challengeResponse.get("data");
        String loginUrl = (String) challengeData.get("loginUrl");
        assertThat(loginUrl)
                .startsWith("https://login.safarigo.test/api/v1/auth/channel/start")
                .doesNotContain("gateway.safarigo.test");

        MvcResult start = mockMvc.perform(get("/api/v1/auth/channel/start")
                        .param("linkToken", queryParam(loginUrl, "linkToken"))
                        .param("authMode", queryParam(loginUrl, "authMode")))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/login"))
                .andReturn();

        assertThat(start.getRequest().getSession(false)).isInstanceOf(MockHttpSession.class);
        MockHttpSession session = (MockHttpSession) start.getRequest().getSession(false);
        mockMvc.perform(get("/login").session(session))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("Welcome back")))
                .andExpect(content().string(containsString("Continuing from WhatsApp")))
                .andExpect(content().string(containsString("action=\"/login\"")))
                .andExpect(content().string(containsString("href=\"/forgot-password\"")))
                .andExpect(content().string(not(containsString("action=\"/api/v1/auth/channel/login\""))));

        mockMvc.perform(post("/login")
                        .with(csrf())
                        .session(session)
                        .param("username", email)
                        .param("password", PASSWORD))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/login/verify"));

        assertThat(emailSender.latestBody()).contains(LOGIN_CODE);
        mockMvc.perform(post("/login/verify")
                        .with(csrf())
                        .session(session)
                        .param("code", LOGIN_CODE))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/api/v1/auth/channel/success"));

        mockMvc.perform(get("/api/v1/whatsapp/auth/status")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + n8nServiceAccessToken())
                        .param("phoneNumber", phoneNumber))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.userId").value(account.getId().toString()))
                .andExpect(jsonPath("$.data.status").value("AUTHENTICATED"));
    }

    @Test
    void forgotPasswordSendsResetLinkAndNewPasswordRequiresLoginVerification() throws Exception {
        emailSender.clear();
        String email = uniqueEmail("forgot");
        String newPassword = "NewPassword123!";
        register(email, uniquePhone());

        mockMvc.perform(get("/forgot-password"))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("Reset password")))
                .andExpect(content().string(containsString("name=\"_csrf\"")));

        MvcResult forgotPassword = mockMvc.perform(post("/forgot-password")
                        .with(csrf())
                        .header("X-Forwarded-Proto", "https")
                        .header("X-Forwarded-Host", "login.safarigo.test")
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .param("email", email))
                .andExpect(status().is3xxRedirection())
                .andReturn();
        assertForgotPasswordSentRedirect(forgotPassword);

        String resetEmailBody = emailSender.latestBody();
        assertThat(resetEmailBody)
                .contains("https://login.safarigo.test/reset-password?token=")
                .doesNotContain("localhost:8080");
        String resetToken = resetTokenFrom(resetEmailBody);
        assertThat(resetToken).isNotBlank();

        mockMvc.perform(get("/reset-password").param("token", resetToken))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("Create new password")))
                .andExpect(content().string(containsString("name=\"token\"")));

        mockMvc.perform(post("/reset-password")
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .param("token", resetToken)
                        .param("password", newPassword)
                        .param("confirmPassword", "Different123!"))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("Check the password details.")));

        mockMvc.perform(post("/reset-password")
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .param("token", resetToken)
                        .param("password", newPassword)
                        .param("confirmPassword", newPassword))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/login?reset=true"));

        MvcResult passwordAccepted = mockMvc.perform(post("/login")
                        .with(csrf())
                        .param("username", email)
                        .param("password", newPassword))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/login/verify"))
                .andReturn();

        MockHttpSession session = (MockHttpSession) passwordAccepted.getRequest().getSession(false);
        mockMvc.perform(post("/login/verify")
                        .with(csrf())
                        .session(session)
                        .param("code", LOGIN_CODE))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/login/success"));

        mockMvc.perform(get("/login/success").session(session))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("Login successful")))
                .andExpect(content().string(containsString("You are now authenticated.")))
                .andExpect(content().string(containsString("action=\"/logout\"")));
    }

    @Test
    void forgotPasswordResetLinkUsesIncomingPublicDomain() throws Exception {
        emailSender.clear();
        String email = uniqueEmail("public-reset-domain");
        register(email, uniquePhone());

        MvcResult forgotPassword = mockMvc.perform(post("/forgot-password")
                        .with(csrf())
                        .header("X-Forwarded-Proto", "https")
                        .header("X-Forwarded-Host", "login.safarigo.test")
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .param("email", email))
                .andExpect(status().is3xxRedirection())
                .andReturn();
        assertForgotPasswordSentRedirect(forgotPassword);

        assertThat(emailSender.latestBody())
                .contains("https://login.safarigo.test/reset-password?token=")
                .doesNotContain("localhost")
                .doesNotContain("127.0.0.1");
    }

    @Test
    void forgotPasswordResetLinkFallsBackToConfiguredPublicDomainWhenIncomingHostIsLocal() throws Exception {
        emailSender.clear();
        String email = uniqueEmail("local-reset-domain");
        register(email, uniquePhone());

        MvcResult forgotPassword = mockMvc.perform(post("/forgot-password")
                        .with(csrf())
                        .header("X-Forwarded-Proto", "http")
                        .header("X-Forwarded-Host", "localhost:8080")
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .param("email", email))
                .andExpect(status().is3xxRedirection())
                .andReturn();
        assertForgotPasswordSentRedirect(forgotPassword);

        assertThat(emailSender.latestBody())
                .contains("https://login.safarigo.test/reset-password?token=")
                .doesNotContain("localhost")
                .doesNotContain("127.0.0.1");
    }

    @Test
    void disabledAndDeletedAccountsCannotAuthenticate() throws Exception {
        String disabledEmail = uniqueEmail("disabled");
        register(disabledEmail, uniquePhone());
        UserAccount disabled = userRepository.findByEmailIgnoreCaseAndDeletedFalse(disabledEmail).orElseThrow();
        disabled.setEnabled(false);
        userRepository.save(disabled);

        mockMvc.perform(post("/login")
                        .with(csrf())
                        .param("username", disabledEmail)
                        .param("password", PASSWORD))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/login?error"));

        String deletedEmail = uniqueEmail("deleted");
        register(deletedEmail, uniquePhone());
        UserAccount deleted = userRepository.findByEmailIgnoreCaseAndDeletedFalse(deletedEmail).orElseThrow();
        deleted.setDeleted(true);
        deleted.setEnabled(false);
        userRepository.save(deleted);

        mockMvc.perform(post("/login")
                        .with(csrf())
                        .param("username", deletedEmail)
                        .param("password", PASSWORD))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/login?error"));
    }

    @Test
    void oidcDiscoveryAndJwksExposePublicMetadataOnly() throws Exception {
        mockMvc.perform(get("/.well-known/openid-configuration"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.issuer").value("http://localhost:8080"))
                .andExpect(jsonPath("$.authorization_endpoint").value("http://localhost:8080/oauth2/authorize"))
                .andExpect(jsonPath("$.token_endpoint").value("http://localhost:8080/oauth2/token"))
                .andExpect(jsonPath("$.userinfo_endpoint").value("http://localhost:8080/userinfo"))
                .andExpect(jsonPath("$.jwks_uri").value("http://localhost:8080/oauth2/jwks"));

        mockMvc.perform(get("/oauth2/jwks"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.keys[0].kty").value("RSA"))
                .andExpect(jsonPath("$.keys[0].kid").value("iam-key-1"))
                .andExpect(jsonPath("$.keys[0].n").exists())
                .andExpect(jsonPath("$.keys[0].e").exists())
                .andExpect(jsonPath("$.keys[0].d").doesNotExist())
                .andExpect(jsonPath("$.keys[0].p").doesNotExist())
                .andExpect(jsonPath("$.keys[0].q").doesNotExist());
    }

    @Test
    void clientCredentialsWorksForN8nAndIssuesExpectedClaims() throws Exception {
        Map<String, Object> tokenResponse = tokenResponse(mockMvc.perform(post("/oauth2/token")
                        .with(httpBasic(N8N_CLIENT_ID, N8N_CLIENT_SECRET))
                        .param(OAuth2ParameterNames.GRANT_TYPE, "client_credentials")
                        .param(OAuth2ParameterNames.SCOPE, "service:n8n travel.create menu:read"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.access_token").exists())
                .andExpect(jsonPath("$.token_type").value("Bearer"))
                .andExpect(jsonPath("$.refresh_token").doesNotExist())
                .andReturn());

        Jwt jwt = jwtDecoder.decode((String) tokenResponse.get("access_token"));
        assertThat(jwt.getIssuer().toString()).isEqualTo("http://localhost:8080");
        assertThat(jwt.getAudience()).contains("travel-platform-api");
        assertThat(jwt.getSubject()).isEqualTo(N8N_CLIENT_ID);
        assertThat(jwt.getClaimAsStringList("roles")).contains("SERVICE");
        assertThat(jwt.getClaimAsStringList("permissions"))
                .contains("service:n8n", "travel.create", "menu:read");
    }

    @Test
    void n8nCanCheckWhatsappRegistrationAndAuthenticationStatus() throws Exception {
        String n8nAccessToken = n8nServiceAccessToken();
        String phoneNumber = uniquePhone();

        mockMvc.perform(get("/api/v1/whatsapp/auth/status")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + n8nAccessToken)
                        .param("phoneNumber", phoneNumber))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.code").value("SUCCESS"))
                .andExpect(jsonPath("$.data.phoneNumber").value(phoneNumber))
                .andExpect(jsonPath("$.data.registered").value(false))
                .andExpect(jsonPath("$.data.authenticated").value(false))
                .andExpect(jsonPath("$.data.status").value("NOT_REGISTERED"));

        String email = uniqueEmail("whatsapp");
        UserAccount account = register(email, phoneNumber);

        mockMvc.perform(get("/api/v1/whatsapp/auth/status")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + n8nAccessToken)
                        .param("phoneNumber", phoneNumber.substring(0, 5) + " " + phoneNumber.substring(5)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.phoneNumber").value(phoneNumber))
                .andExpect(jsonPath("$.data.registered").value(true))
                .andExpect(jsonPath("$.data.authenticated").value(false))
                .andExpect(jsonPath("$.data.userId").value(account.getId().toString()))
                .andExpect(jsonPath("$.data.status").value("AUTHENTICATION_REQUIRED"));

        issueTravelWebTokens(email);

        mockMvc.perform(get("/api/v1/whatsapp/auth/status")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + n8nAccessToken)
                        .param("phoneNumber", phoneNumber))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.registered").value(true))
                .andExpect(jsonPath("$.data.authenticated").value(true))
                .andExpect(jsonPath("$.data.userId").value(account.getId().toString()))
                .andExpect(jsonPath("$.data.status").value("AUTHENTICATED"));
    }

    @Test
    void n8nCanLogoutUserByEmailOrPhoneNumber() throws Exception {
        String n8nAccessToken = n8nServiceAccessToken();
        String email = uniqueEmail("logout-email");
        UserAccount account = register(email, uniquePhone());
        issueTravelWebTokens(email);
        assertThat(activeAuthorizationCount(account)).isGreaterThan(0);
        assertThat(activeRefreshTokenCount(account)).isGreaterThan(0);

        mockMvc.perform(post("/api/v1/auth/logout")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + n8nAccessToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(Map.of(
                                "email", email.toUpperCase(Locale.ROOT)
                        ))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.code").value("SUCCESS"))
                .andExpect(jsonPath("$.message").value("User logout processed"))
                .andExpect(jsonPath("$.data.userId").value(account.getId().toString()))
                .andExpect(jsonPath("$.data.email").value(email))
                .andExpect(jsonPath("$.data.activeAuthorizations").value(1))
                .andExpect(jsonPath("$.data.activeRefreshTokens").value(1))
                .andExpect(jsonPath("$.data.revokedAuthorizations").value(1))
                .andExpect(jsonPath("$.data.revokedRefreshTokens").value(1))
                .andExpect(jsonPath("$.data.revokedChannelAuthentications").value(0));

        assertThat(activeAuthorizationCount(account)).isZero();
        assertThat(activeRefreshTokenCount(account)).isZero();

        String phoneNumber = uniquePhone();
        String phoneEmail = uniqueEmail("logout-phone");
        UserAccount phoneAccount = register(phoneEmail, phoneNumber);
        issueTravelWebTokens(phoneEmail);
        recordActiveWhatsappAuthentication(phoneAccount, phoneNumber);

        mockMvc.perform(get("/api/v1/whatsapp/auth/status")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + n8nAccessToken)
                        .param("phoneNumber", phoneNumber))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.authenticated").value(true))
                .andExpect(jsonPath("$.data.status").value("AUTHENTICATED"));

        mockMvc.perform(post("/api/v1/auth/logout")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + n8nAccessToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(Map.of(
                                "phoneNumber", phoneNumber.substring(0, 5) + " " + phoneNumber.substring(5)
                        ))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.userId").value(phoneAccount.getId().toString()))
                .andExpect(jsonPath("$.data.phoneNumber").value(phoneNumber))
                .andExpect(jsonPath("$.data.revokedAuthorizations").value(1))
                .andExpect(jsonPath("$.data.revokedRefreshTokens").value(1))
                .andExpect(jsonPath("$.data.revokedChannelAuthentications").value(1));

        assertThat(activeAuthorizationCount(phoneAccount)).isZero();
        assertThat(activeRefreshTokenCount(phoneAccount)).isZero();
        mockMvc.perform(get("/api/v1/whatsapp/auth/status")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + n8nAccessToken)
                        .param("phoneNumber", phoneNumber))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.authenticated").value(false))
                .andExpect(jsonPath("$.data.status").value("AUTHENTICATION_REQUIRED"));
    }

    @Test
    void logoutByIdentifierRequiresServiceOrAdminAuthority() throws Exception {
        String email = uniqueEmail("logout-denied");
        UserAccount account = register(email, uniquePhone());
        Map<String, Object> tokenResponse = issueTravelWebTokens(email);
        String travellerAccessToken = (String) tokenResponse.get("access_token");

        mockMvc.perform(post("/api/v1/auth/logout")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + travellerAccessToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(Map.of("email", email))))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.code").value("FORBIDDEN"));

        assertThat(activeAuthorizationCount(account)).isGreaterThan(0);
        assertThat(activeRefreshTokenCount(account)).isGreaterThan(0);
    }

    @Test
    @SuppressWarnings("unchecked")
    void n8nCanIssueDelegatedTravellerTokenForAuthenticatedWhatsappUser() throws Exception {
        String n8nAccessToken = n8nServiceAccessToken();
        String phoneNumber = uniquePhone();
        String email = uniqueEmail("delegated");
        UserAccount account = register(email, phoneNumber);
        issueTravelWebTokens(email);

        MvcResult result = mockMvc.perform(post("/api/v1/whatsapp/auth/tokens")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + n8nAccessToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(Map.of(
                                "phoneNumber", phoneNumber,
                                "scope", "travel:create"
                        ))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.code").value("SUCCESS"))
                .andExpect(jsonPath("$.data.authenticated").value(true))
                .andExpect(jsonPath("$.data.userId").value(account.getId().toString()))
                .andExpect(jsonPath("$.data.actor").value(N8N_CLIENT_ID))
                .andExpect(jsonPath("$.data.tokenType").value("Bearer"))
                .andExpect(jsonPath("$.data.accessToken").exists())
                .andReturn();

        Map<String, Object> response = tokenResponse(result);
        Map<String, Object> data = (Map<String, Object>) response.get("data");
        Jwt delegatedToken = jwtDecoder.decode((String) data.get("accessToken"));

        assertThat(delegatedToken.getIssuer().toString()).isEqualTo("http://localhost:8080");
        assertThat(delegatedToken.getAudience()).contains("travel-platform-api");
        assertThat(delegatedToken.getSubject()).isEqualTo(account.getId().toString());
        assertThat(delegatedToken.getClaimAsStringList("roles")).contains("TRAVELLER");
        assertThat(delegatedToken.getClaimAsStringList("permissions")).containsExactly("travel:create");
        assertThat(delegatedToken.getClaimAsStringList("scope")).containsExactly("travel:create");
        assertThat((Boolean) delegatedToken.getClaim("delegated")).isTrue();
        assertThat(delegatedToken.getClaimAsString("auth_method")).isEqualTo("WHATSAPP");
        assertThat((Map<String, Object>) delegatedToken.getClaim("act"))
                .containsEntry("sub", N8N_CLIENT_ID)
                .containsEntry("client_id", N8N_CLIENT_ID);
    }

    @Test
    void delegatedTravellerTokenRequiresAuthenticatedWhatsappUserAndAllowedScope() throws Exception {
        String n8nAccessToken = n8nServiceAccessToken();
        String phoneNumber = uniquePhone();
        String email = uniqueEmail("delegated-denied");
        register(email, phoneNumber);

        mockMvc.perform(post("/api/v1/whatsapp/auth/tokens")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + n8nAccessToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(Map.of(
                                "phoneNumber", phoneNumber,
                                "scope", "travel:create"
                        ))))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.code").value("FORBIDDEN"));

        issueTravelWebTokens(email);

        mockMvc.perform(post("/api/v1/whatsapp/auth/tokens")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + n8nAccessToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(Map.of(
                                "phoneNumber", phoneNumber,
                                "scope", "menu:delete"
                        ))))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.code").value("FORBIDDEN"));
    }

    @Test
    void apiEndpointsReturnJsonUnauthorizedInsteadOfLoginPage() throws Exception {
        mockMvc.perform(get("/api/v1/whatsapp/auth/status")
                        .accept(MediaType.APPLICATION_JSON)
                        .param("phoneNumber", uniquePhone()))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.code").value("UNAUTHORIZED"))
                .andExpect(jsonPath("$.message").value("Authentication is required"));
    }

    @Test
    void authorizationCodeWithPkceUserInfoAndRefreshRotationWork() throws Exception {
        String email = uniqueEmail("oidc");
        UserAccount account = register(email, uniquePhone());
        Map<String, Object> tokenResponse = issueTravelWebTokens(email);

        String accessToken = (String) tokenResponse.get("access_token");
        Jwt jwt = jwtDecoder.decode(accessToken);
        assertThat(jwt.getIssuer().toString()).isEqualTo("http://localhost:8080");
        assertThat(jwt.getSubject()).isEqualTo(account.getId().toString());
        assertThat(jwt.getAudience()).contains("travel-platform-api");
        assertThat(jwt.getExpiresAt()).isAfter(jwt.getIssuedAt());
        assertThat(jwt.getClaimAsStringList("roles")).contains("TRAVELLER");
        assertThat(jwt.getClaimAsStringList("permissions")).contains("travel:read", "travel:create");

        mockMvc.perform(get("/userinfo")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.sub").value(account.getId().toString()))
                .andExpect(jsonPath("$.given_name").value("Test"))
                .andExpect(jsonPath("$.family_name").value("User"))
                .andExpect(jsonPath("$.email").value(email))
                .andExpect(jsonPath("$.email_verified").value(false))
                .andExpect(jsonPath("$.phone_number").value(account.getPhoneNumber()))
                .andExpect(jsonPath("$.password").doesNotExist());

        String refreshToken = (String) tokenResponse.get("refresh_token");
        Map<String, Object> rotatedResponse = tokenResponse(mockMvc.perform(post("/oauth2/token")
                        .with(httpBasic(TRAVEL_WEB_CLIENT_ID, TRAVEL_WEB_CLIENT_SECRET))
                        .param(OAuth2ParameterNames.GRANT_TYPE, "refresh_token")
                        .param("refresh_token", refreshToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.refresh_token").exists())
                .andReturn());

        String rotatedRefreshToken = (String) rotatedResponse.get("refresh_token");
        assertThat(rotatedRefreshToken).isNotEqualTo(refreshToken);

        mockMvc.perform(post("/oauth2/token")
                        .with(httpBasic(TRAVEL_WEB_CLIENT_ID, TRAVEL_WEB_CLIENT_SECRET))
                        .param(OAuth2ParameterNames.GRANT_TYPE, "refresh_token")
                        .param("refresh_token", refreshToken))
                .andExpect(status().isBadRequest());

        mockMvc.perform(post("/oauth2/token")
                        .with(httpBasic(TRAVEL_WEB_CLIENT_ID, TRAVEL_WEB_CLIENT_SECRET))
                        .param(OAuth2ParameterNames.GRANT_TYPE, "refresh_token")
                        .param("refresh_token", rotatedRefreshToken))
                .andExpect(status().isBadRequest());
    }

    private String n8nServiceAccessToken() throws Exception {
        return n8nServiceAccessToken("service:n8n");
    }

    private String n8nServiceAccessToken(String scope) throws Exception {
        Map<String, Object> tokenResponse = tokenResponse(mockMvc.perform(post("/oauth2/token")
                        .with(httpBasic(N8N_CLIENT_ID, N8N_CLIENT_SECRET))
                        .param(OAuth2ParameterNames.GRANT_TYPE, "client_credentials")
                        .param(OAuth2ParameterNames.SCOPE, scope))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.access_token").exists())
                .andReturn());

        return (String) tokenResponse.get("access_token");
    }

    private Map<String, Object> issueTravelWebTokens(String email) throws Exception {
        Pkce pkce = pkce();

        MockHttpSession session = loginSession(email);
        MvcResult authorization = mockMvc.perform(get(authorizationUri(pkce))
                        .session(session))
                .andExpect(status().is3xxRedirection())
                .andReturn();

        String code = queryParam(authorization.getResponse().getRedirectedUrl(), OAuth2ParameterNames.CODE);
        assertThat(code).isNotBlank();

        return tokenResponse(mockMvc.perform(post("/oauth2/token")
                        .with(httpBasic(TRAVEL_WEB_CLIENT_ID, TRAVEL_WEB_CLIENT_SECRET))
                        .param(OAuth2ParameterNames.GRANT_TYPE, "authorization_code")
                        .param(OAuth2ParameterNames.CODE, code)
                        .param(OAuth2ParameterNames.REDIRECT_URI, REDIRECT_URI)
                        .param("code_verifier", pkce.verifier()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.access_token").exists())
                .andExpect(jsonPath("$.refresh_token").exists())
                .andExpect(jsonPath("$.id_token").exists())
                .andReturn());
    }

    private UserAccount register(String email, String phoneNumber) throws Exception {
        mockMvc.perform(post("/api/v1/users/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(Map.of(
                                "firstName", "Test",
                                "lastName", "User",
                                "email", email,
                                "password", PASSWORD,
                                "phoneNumber", phoneNumber
                        ))))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.code").value("CREATED"))
                .andExpect(jsonPath("$.data.email").value(email));

        return userRepository.findByEmailIgnoreCaseAndDeletedFalse(email).orElseThrow();
    }

    private MockHttpSession loginSession(String email) throws Exception {
        MvcResult login = mockMvc.perform(post("/login")
                        .with(csrf())
                        .param("username", email)
                        .param("password", PASSWORD))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/login/verify"))
                .andReturn();

        assertThat(login.getRequest().getSession(false)).isInstanceOf(MockHttpSession.class);
        MockHttpSession session = (MockHttpSession) login.getRequest().getSession(false);

        mockMvc.perform(post("/login/verify")
                        .with(csrf())
                        .session(session)
                        .param("code", LOGIN_CODE))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/login/success"));

        return session;
    }

    private void recordActiveWhatsappAuthentication(UserAccount account, String phoneNumber) {
        Instant now = Instant.now();
        jdbcTemplate.update(
                """
                insert into channel_authentications (
                    id,
                    channel,
                    phone_number,
                    user_id,
                    authenticated_at,
                    expires_at,
                    created_at,
                    updated_at
                )
                values (?, 'WHATSAPP', ?, ?, ?, ?, ?, ?)
                """,
                UUID.randomUUID(),
                phoneNumber,
                account.getId(),
                Timestamp.from(now),
                Timestamp.from(now.plusSeconds(604_800)),
                Timestamp.from(now),
                Timestamp.from(now)
        );
    }

    private String resetTokenFrom(String emailBody) {
        Matcher matcher = Pattern.compile("token=([^\\s]+)").matcher(emailBody);
        assertThat(matcher.find()).isTrue();
        return matcher.group(1);
    }

    private void assertForgotPasswordSentRedirect(MvcResult result) {
        assertThat(result.getResponse().getRedirectedUrl()).endsWith("/forgot-password?sent=true");
    }

    private Map<String, Object> tokenResponse(MvcResult result) throws Exception {
        return objectMapper.readValue(
                result.getResponse().getContentAsString(),
                new TypeReference<>() {
                }
        );
    }

    private String queryParam(String location, String name) {
        assertThat(location).isNotBlank();
        return UriComponentsBuilder.fromUriString(location).build().getQueryParams().getFirst(name);
    }

    private String authorizationUri(Pkce pkce) {
        return UriComponentsBuilder.fromPath("/oauth2/authorize")
                .queryParam(OAuth2ParameterNames.RESPONSE_TYPE, "code")
                .queryParam(OAuth2ParameterNames.CLIENT_ID, TRAVEL_WEB_CLIENT_ID)
                .queryParam(OAuth2ParameterNames.REDIRECT_URI, REDIRECT_URI)
                .queryParam(OAuth2ParameterNames.SCOPE,
                        OidcScopes.OPENID + " " + OidcScopes.PROFILE + " " + OidcScopes.EMAIL + " " + OidcScopes.PHONE)
                .queryParam(OAuth2ParameterNames.STATE, "local-state")
                .queryParam("code_challenge", pkce.challenge())
                .queryParam("code_challenge_method", "S256")
                .build()
                .toUriString();
    }

    private String uniqueEmail(String prefix) {
        return prefix + "-" + UUID.randomUUID() + "@example.com";
    }

    private String uniquePhone() {
        return "2547" + String.format(Locale.ROOT, "%08d", Math.abs(UUID.randomUUID().getMostSignificantBits() % 100_000_000L));
    }

    private long activeAuthorizationCount(UserAccount account) {
        Long count = jdbcTemplate.queryForObject(
                """
                select count(*)
                from oauth2_authorization
                where principal_name = ? or principal_name = ?
                """,
                Long.class,
                account.getId().toString(),
                account.getEmail()
        );

        return count == null ? 0 : count;
    }

    private long activeRefreshTokenCount(UserAccount account) {
        Long count = jdbcTemplate.queryForObject(
                """
                select count(*)
                from oauth2_refresh_tokens
                where (principal_name = ? or principal_name = ?)
                  and revoked_at is null
                """,
                Long.class,
                account.getId().toString(),
                account.getEmail()
        );

        return count == null ? 0 : count;
    }

    private Pkce pkce() throws Exception {
        String verifier = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~abcdefghijk";
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        String challenge = Base64.getUrlEncoder()
                .withoutPadding()
                .encodeToString(digest.digest(verifier.getBytes(StandardCharsets.US_ASCII)));
        return new Pkce(verifier, challenge);
    }

    private record Pkce(String verifier, String challenge) {
    }

    @TestConfiguration
    static class TestBeans {

        @Bean
        @Primary
        VerificationCodeGenerator verificationCodeGenerator() {
            return () -> LOGIN_CODE;
        }

        @Bean
        @Primary
        CapturingIdentityEmailSender capturingIdentityEmailSender() {
            return new CapturingIdentityEmailSender();
        }
    }

    static class CapturingIdentityEmailSender implements IdentityEmailSender {

        private final List<EmailMessage> messages = new ArrayList<>();

        @Override
        public void sendEmailWithVerificationCode(String toEmail, String subject, String text) {
            messages.add(new EmailMessage(toEmail, subject, text));
        }

        void clear() {
            messages.clear();
        }

        String latestBody() {
            assertThat(messages).isNotEmpty();
            return messages.get(messages.size() - 1).text();
        }
    }

    private record EmailMessage(String toEmail, String subject, String text) {
    }
}
