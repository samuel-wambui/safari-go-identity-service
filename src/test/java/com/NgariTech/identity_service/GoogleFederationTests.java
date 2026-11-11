package com.NgariTech.identity_service;

import com.NgariTech.identity_service.auth.channel.ChannelLinkChallenge;
import com.NgariTech.identity_service.auth.channel.ChannelLinkChallengeRepository;
import com.NgariTech.identity_service.auth.channel.ChannelLinkChallengeService;
import com.NgariTech.identity_service.auth.channel.dto.CreateChannelLinkChallengeRequest;
import com.NgariTech.identity_service.auth.channel.dto.CreateChannelLinkChallengeResponse;
import com.NgariTech.identity_service.auth.google.GoogleOAuth2SuccessHandler;
import com.NgariTech.identity_service.auth.google.ExternalIdentityProvider;
import com.NgariTech.identity_service.auth.google.ExternalIdentityRepository;
import com.NgariTech.identity_service.auth.google.GoogleAuthenticationException;
import com.NgariTech.identity_service.auth.google.GoogleFederationService;
import com.NgariTech.identity_service.auth.google.GoogleLoginSession;
import com.NgariTech.identity_service.role.RoleNames;
import com.NgariTech.identity_service.role.RoleRepository;
import com.NgariTech.identity_service.user.UserAccount;
import com.NgariTech.identity_service.user.UserRepository;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.StandardClaimNames;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.web.util.UriComponentsBuilder;
import tools.jackson.core.type.TypeReference;
import tools.jackson.databind.ObjectMapper;

import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.not;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.options;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest(properties = "iam.public-base-url=https://iam.configured.test")
@AutoConfigureMockMvc
class GoogleFederationTests {

    private static final String N8N_CLIENT_ID = "n8n-orchestrator";
    private static final String N8N_CLIENT_SECRET = "n8n-dev-secret";
    private static final String PASSWORD = "Password123!";

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private GoogleFederationService googleFederationService;

    @Autowired
    private GoogleOAuth2SuccessHandler googleOAuth2SuccessHandler;

    @Autowired
    private ChannelLinkChallengeService channelLinkChallengeService;

    @Autowired
    private ChannelLinkChallengeRepository channelLinkChallengeRepository;

    @Autowired
    private ExternalIdentityRepository externalIdentityRepository;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private RoleRepository roleRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    @Qualifier("resourceServerJwtDecoder")
    private JwtDecoder jwtDecoder;

    @Test
    void n8nCreatesWhatsappGoogleLinkChallengeOnIdentityHostAndStartStoresChallengeInSession() throws Exception {
        String accessToken = n8nServiceAccessToken("service:n8n channel_auth:create");
        String phoneNumber = uniquePhone();

        MvcResult result = mockMvc.perform(post("/api/v1/whatsapp/auth/challenges")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken)
                        .header("X-Forwarded-Proto", "https")
                        .header("X-Forwarded-Host", "gateway.safarigo.test")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(Map.of("phoneNumber", phoneNumber))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.code").value("SUCCESS"))
                .andExpect(jsonPath("$.data.registrationUrl").exists())
                .andExpect(jsonPath("$.data.loginUrl").exists())
                .andExpect(jsonPath("$.data.expiresAt").exists())
                .andReturn();

        String registrationUrl = nestedString(result, "data", "registrationUrl");
        String loginUrl = nestedString(result, "data", "loginUrl");
        assertThat(registrationUrl)
                .startsWith("https://iam.configured.test/api/v1/auth/channel/start")
                .doesNotContain("gateway.safarigo.test");
        assertThat(loginUrl)
                .startsWith("https://iam.configured.test/api/v1/auth/channel/start")
                .doesNotContain("gateway.safarigo.test");
        assertThat(registrationUrl).contains("/api/v1/auth/channel/start");
        assertThat(loginUrl).contains("/api/v1/auth/channel/start");
        assertThat(queryParam(registrationUrl, "authMode")).isEqualTo("register");
        assertThat(queryParam(loginUrl, "authMode")).isEqualTo("login");
        String linkToken = queryParam(registrationUrl, "linkToken");
        assertThat(queryParam(loginUrl, "linkToken")).isEqualTo(linkToken);

        MvcResult start = mockMvc.perform(get("/api/v1/auth/google/start")
                        .param("linkToken", linkToken))
                .andExpect(status().is3xxRedirection())
                .andExpect(header().string(HttpHeaders.LOCATION, "/oauth2/authorization/google"))
                .andReturn();

        assertThat(start.getRequest().getSession(false)).isInstanceOf(MockHttpSession.class);
        MockHttpSession session = (MockHttpSession) start.getRequest().getSession(false);
        assertThat(session.getAttribute(GoogleLoginSession.CHANNEL_LINK_CHALLENGE_ID)).isInstanceOf(UUID.class);

        MvcResult channelStart = mockMvc.perform(get("/api/v1/auth/channel/start")
                        .param("linkToken", linkToken)
                        .param("authMode", queryParam(registrationUrl, "authMode")))
                .andExpect(status().is3xxRedirection())
                .andExpect(header().string(HttpHeaders.LOCATION, "/api/v1/auth/channel/continue#register"))
                .andReturn();

        MvcResult loginStart = mockMvc.perform(get("/api/v1/auth/channel/start")
                        .param("linkToken", queryParam(loginUrl, "linkToken"))
                        .param("authMode", queryParam(loginUrl, "authMode")))
                .andExpect(status().is3xxRedirection())
                .andExpect(header().string(HttpHeaders.LOCATION, "/login"))
                .andReturn();

        MockHttpSession loginSession = (MockHttpSession) loginStart.getRequest().getSession(false);
        mockMvc.perform(get("/login")
                        .session(loginSession))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("Welcome back")))
                .andExpect(content().string(containsString("Continuing from WhatsApp")))
                .andExpect(content().string(containsString("action=\"/login\"")))
                .andExpect(content().string(containsString("href=\"/forgot-password\"")))
                .andExpect(content().string(not(containsString("action=\"/api/v1/auth/channel/login\""))));

        MockHttpSession channelSession = (MockHttpSession) channelStart.getRequest().getSession(false);
        mockMvc.perform(get("/api/v1/auth/channel/continue")
                        .session(channelSession))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("Continuing from WhatsApp")))
                .andExpect(content().string(containsString("Continue with Google")))
                .andExpect(content().string(containsString("Create account")))
                .andExpect(content().string(containsString("href=\"/forgot-password\"")))
                .andExpect(content().string(not(containsString("href=\"#password-reset\""))))
                .andExpect(content().string(containsString("name=\"_csrf\"")))
                .andExpect(content().string(not(containsString(phoneNumber))))
                .andExpect(content().string(not(containsString(linkToken))));
    }

    @Test
    void mobileGoogleStartStoresRedirectUriAndStartsGoogleAuthorization() throws Exception {
        MvcResult start = mockMvc.perform(get("/api/v1/mobile/auth/google/start")
                        .param("redirectUri", "safarigo://auth/google")
                        .param("traceId", "sg-test-trace-1234"))
                .andExpect(status().is3xxRedirection())
                .andExpect(header().string(HttpHeaders.LOCATION, "/oauth2/authorization/google?prompt=select_account"))
                .andReturn();

        assertThat(start.getRequest().getSession(false)).isInstanceOf(MockHttpSession.class);
        MockHttpSession session = (MockHttpSession) start.getRequest().getSession(false);
        assertThat(session.getAttribute(GoogleLoginSession.MOBILE_REDIRECT_URI)).isEqualTo("safarigo://auth/google");
        assertThat(session.getAttribute(GoogleLoginSession.MOBILE_TRACE_ID)).isEqualTo("sg-test-trace-1234");
    }

    @Test
    void mobileGoogleSuccessReturnsOneTimeCodeThatExchangesForMobileToken() throws Exception {
        String phoneNumber = uniquePhone();
        String email = uniqueEmail("mobile-google");
        UserAccount account = localUser(email, phoneNumber, true);
        linkGoogleIdentity(account, "google-sub-mobile");

        MockHttpSession session = new MockHttpSession();
        session.setAttribute(GoogleLoginSession.MOBILE_REDIRECT_URI, "safarigo://auth/google");
        session.setAttribute(GoogleLoginSession.MOBILE_TRACE_ID, "sg-success-trace-1234");
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setSession(session);
        request.setRemoteAddr("127.0.0.1");
        request.addHeader(HttpHeaders.USER_AGENT, "mobile-test");
        MockHttpServletResponse response = new MockHttpServletResponse();

        OidcUser oidcUser = googleUser("google-sub-mobile", email, true, "Mobile", "Google");
        googleOAuth2SuccessHandler.onAuthenticationSuccess(
                request,
                response,
                UsernamePasswordAuthenticationToken.authenticated(
                        oidcUser,
                        "GOOGLE",
                        List.of(new SimpleGrantedAuthority("OIDC_USER"))
                )
        );

        String redirectUrl = response.getRedirectedUrl();
        assertThat(redirectUrl).startsWith("safarigo://auth/google?code=");
        assertThat(session.getAttribute(GoogleLoginSession.MOBILE_REDIRECT_URI)).isNull();
        assertThat(session.getAttribute(GoogleLoginSession.MOBILE_TRACE_ID)).isNull();
        String code = queryParam(redirectUrl, "code");
        assertThat(code).isNotBlank();
        assertThat(queryParam(redirectUrl, "traceId")).isEqualTo("sg-success-trace-1234");

        MvcResult exchange = mockMvc.perform(post("/api/v1/mobile/auth/google/exchange")
                        .header("X-SafariGo-Mobile-Trace-Id", "sg-success-trace-1234")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(Map.of("code", code))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.code").value("SUCCESS"))
                .andExpect(jsonPath("$.message").value("Mobile Google login successful"))
                .andExpect(jsonPath("$.data.userId").value(account.getId().toString()))
                .andExpect(jsonPath("$.data.mobileSessionId").exists())
                .andExpect(jsonPath("$.data.email").value(email))
                .andExpect(jsonPath("$.data.phoneNumber").value(phoneNumber))
                .andExpect(jsonPath("$.data.firstName").value("Local"))
                .andExpect(jsonPath("$.data.lastName").value("User"))
                .andExpect(jsonPath("$.data.tokenType").value("Bearer"))
                .andExpect(jsonPath("$.data.accessToken").exists())
                .andExpect(jsonPath("$.data.refreshToken").doesNotExist())
                .andReturn();

        Jwt mobileToken = jwtDecoder.decode(nestedString(exchange, "data", "accessToken"));
        assertThat(mobileToken.getSubject()).isEqualTo(account.getId().toString());
        assertThat(mobileToken.getClaimAsString("mobile_session_id")).isEqualTo(nestedString(exchange, "data", "mobileSessionId"));
        assertThat(mobileToken.getClaimAsString("client_id")).isEqualTo("safarigo-mobile");
        assertThat(mobileToken.getClaimAsString("email")).isEqualTo(email);
        assertThat(mobileToken.getClaimAsString("phone_number")).isEqualTo(phoneNumber);
        assertThat(mobileToken.getClaimAsString("auth_method")).isEqualTo("MOBILE_GOOGLE");

        mockMvc.perform(post("/api/v1/mobile/auth/google/exchange")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(Map.of("code", code))))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.code").value("UNAUTHORIZED"));
    }

    @Test
    void n8nChallengeUsesConfiguredIdentityHostBeforeLoginUrl() throws Exception {
        String accessToken = n8nServiceAccessToken("service:n8n channel_auth:create");

        MvcResult result = mockMvc.perform(post("/api/v1/whatsapp/auth/challenges")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken)
                        .header("X-Forwarded-Proto", "http")
                        .header("X-Forwarded-Host", "localhost:8080")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(Map.of(
                                "phoneNumber", uniquePhone(),
                                "loginUrl", "https://iam.from-login-link.test/login?continue=/booking"
                        ))))
                .andExpect(status().isOk())
                .andReturn();

        String registrationUrl = nestedString(result, "data", "registrationUrl");
        String loginUrl = nestedString(result, "data", "loginUrl");

        assertThat(registrationUrl)
                .startsWith("https://iam.configured.test/api/v1/auth/channel/start")
                .doesNotContain("localhost")
                .doesNotContain("iam.from-login-link.test")
                .doesNotContain("/login");
        assertThat(loginUrl)
                .startsWith("https://iam.configured.test/api/v1/auth/channel/start")
                .doesNotContain("localhost")
                .doesNotContain("iam.from-login-link.test")
                .doesNotContain("/login");
        assertThat(queryParam(registrationUrl, "authMode")).isEqualTo("register");
        assertThat(queryParam(loginUrl, "authMode")).isEqualTo("login");
        assertThat(queryParam(loginUrl, "linkToken")).isEqualTo(queryParam(registrationUrl, "linkToken"));
    }

    @Test
    void n8nChallengeFallsBackToConfiguredPublicBaseUrlWhenRequestHostIsLocalAndLoginUrlIsMissing() throws Exception {
        String accessToken = n8nServiceAccessToken("service:n8n channel_auth:create");

        MvcResult result = mockMvc.perform(post("/api/v1/whatsapp/auth/challenges")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken)
                        .header("X-Forwarded-Proto", "http")
                        .header("X-Forwarded-Host", "localhost:8080")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(Map.of("phoneNumber", uniquePhone()))))
                .andExpect(status().isOk())
                .andReturn();

        String registrationUrl = nestedString(result, "data", "registrationUrl");
        String loginUrl = nestedString(result, "data", "loginUrl");

        assertThat(registrationUrl)
                .startsWith("https://iam.configured.test/api/v1/auth/channel/start")
                .doesNotContain("localhost")
                .doesNotContain("127.0.0.1");
        assertThat(loginUrl)
                .startsWith("https://iam.configured.test/api/v1/auth/channel/start")
                .doesNotContain("localhost")
                .doesNotContain("127.0.0.1");
        assertThat(queryParam(registrationUrl, "authMode")).isEqualTo("register");
        assertThat(queryParam(loginUrl, "authMode")).isEqualTo("login");
        assertThat(queryParam(loginUrl, "linkToken")).isEqualTo(queryParam(registrationUrl, "linkToken"));
    }

    @Test
    void whatsappChallengeAcceptsCorsPreflightFromAnyOrigin() throws Exception {
        mockMvc.perform(options("/api/v1/whatsapp/auth/challenges")
                        .header(HttpHeaders.ORIGIN, "https://caller.any-domain.test")
                        .header(HttpHeaders.ACCESS_CONTROL_REQUEST_METHOD, "POST")
                        .header(HttpHeaders.ACCESS_CONTROL_REQUEST_HEADERS, "authorization,content-type"))
                .andExpect(status().isOk())
                .andExpect(header().string(HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN, "https://caller.any-domain.test"))
                .andExpect(header().string(HttpHeaders.ACCESS_CONTROL_ALLOW_METHODS, containsString("POST")));
    }

    @Test
    void channelPageCanRegisterLocalAccountUsingWhatsappChallengePhone() throws Exception {
        String phoneNumber = uniquePhone();
        MockHttpSession session = startChannelSession(createChallengeUrl(phoneNumber));
        String email = uniqueEmail("channel-register");

        mockMvc.perform(post("/api/v1/auth/channel/register")
                        .with(csrf())
                        .session(session)
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .param("firstName", "Local")
                        .param("lastName", "Traveller")
                        .param("email", email)
                        .param("password", PASSWORD)
                        .param("confirmPassword", PASSWORD))
                .andExpect(status().is3xxRedirection())
                .andExpect(header().string(HttpHeaders.LOCATION, "/api/v1/auth/channel/success"));

        UserAccount account = userRepository.findByEmailIgnoreCaseAndDeletedFalse(email).orElseThrow();
        assertThat(account.getPhoneNumber()).isEqualTo(phoneNumber);
        assertThat(account.getRoleId()).isEqualTo(RoleNames.TRAVELLER_ID);
        assertThat(account.isPasswordLoginEnabled()).isTrue();
    }

    @Test
    void channelPageCanLoginLocalAccountWhenPhoneMatchesChallenge() throws Exception {
        String phoneNumber = uniquePhone();
        String email = uniqueEmail("channel-login");
        UserAccount account = localUser(email, phoneNumber, true);
        MockHttpSession session = startChannelSession(createChallengeUrl(phoneNumber));

        mockMvc.perform(post("/api/v1/auth/channel/login")
                        .with(csrf())
                        .session(session)
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .param("email", email)
                        .param("password", PASSWORD))
                .andExpect(status().is3xxRedirection())
                .andExpect(header().string(HttpHeaders.LOCATION, "/api/v1/auth/channel/success"));

        String accessToken = n8nServiceAccessToken("service:n8n");
        mockMvc.perform(get("/api/v1/whatsapp/auth/status")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken)
                        .param("phoneNumber", phoneNumber))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.userId").value(account.getId().toString()))
                .andExpect(jsonPath("$.data.status").value("AUTHENTICATED"));
    }

    @Test
    void channelPageRejectsLocalLoginWhenPhoneDoesNotMatchChallenge() throws Exception {
        String email = uniqueEmail("channel-login-mismatch");
        localUser(email, uniquePhone(), true);
        MockHttpSession session = startChannelSession(createChallengeUrl(uniquePhone()));

        mockMvc.perform(post("/api/v1/auth/channel/login")
                        .with(csrf())
                        .session(session)
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .param("email", email)
                        .param("password", PASSWORD))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("Invalid credentials or account unavailable")));
    }

    @Test
    void googleRegistersNewTravellerUsingValidWhatsappChallenge() {
        String phoneNumber = uniquePhone();
        UUID challengeId = challengeId(phoneNumber);
        String email = uniqueEmail("google-register");

        UserAccount account = googleFederationService.authenticate(
                googleUser("google-sub-register", email, true, "Grace", "Traveller"),
                challengeId,
                null,
                null
        );

        UserAccount saved = userRepository.findByIdAndDeletedFalse(account.getId()).orElseThrow();
        assertThat(saved.getEmail()).isEqualTo(email);
        assertThat(saved.getPhoneNumber()).isEqualTo(phoneNumber);
        assertThat(saved.getRoleId()).isEqualTo(RoleNames.TRAVELLER_ID);
        assertThat(saved.isEmailVerified()).isTrue();
        assertThat(saved.isPasswordLoginEnabled()).isFalse();
        assertThat(saved.getLastAuthenticationMethod()).isEqualTo("GOOGLE");
        assertThat(externalIdentityRepository.findByProviderAndProviderSubject(
                ExternalIdentityProvider.GOOGLE,
                "google-sub-register"
        )).isPresent();
    }

    @Test
    void linkedGoogleIdentityCanLoginWithoutAChallenge() {
        String phoneNumber = uniquePhone();
        String email = uniqueEmail("google-linked");

        UserAccount firstLogin = googleFederationService.authenticate(
                googleUser("google-sub-linked", email, true, "Linked", "Traveller"),
                challengeId(phoneNumber),
                null,
                null
        );

        UserAccount secondLogin = googleFederationService.authenticate(
                googleUser("google-sub-linked", email, true, "Linked", "Traveller"),
                null,
                null,
                null
        );

        assertThat(secondLogin.getId()).isEqualTo(firstLogin.getId());
        assertThat(secondLogin.getRoleId()).isEqualTo(RoleNames.TRAVELLER_ID);
    }

    @Test
    void googleLinksExistingVerifiedPhoneAccountAndPreservesRole() {
        String phoneNumber = uniquePhone();
        String email = uniqueEmail("google-link-existing");
        UserAccount local = localUser(email, phoneNumber, true);

        UserAccount linked = googleFederationService.authenticate(
                googleUser("google-sub-existing", email, true, "Existing", "Traveller"),
                challengeId(phoneNumber),
                null,
                null
        );

        assertThat(linked.getId()).isEqualTo(local.getId());
        assertThat(linked.getRoleId()).isEqualTo(RoleNames.TRAVELLER_ID);
        assertThat(externalIdentityRepository.findByUserIdAndProvider(local.getId(), ExternalIdentityProvider.GOOGLE))
                .isPresent();
    }

    @Test
    void googleRejectsInvalidProfilesExpiredAndReusedChallenges() {
        assertThatThrownBy(() -> googleFederationService.authenticate(
                googleUser("google-sub-unverified", uniqueEmail("unverified"), false, "Unverified", "User"),
                challengeId(uniquePhone()),
                null,
                null
        )).isInstanceOf(GoogleAuthenticationException.class);

        assertThatThrownBy(() -> googleFederationService.authenticate(
                googleUser(null, uniqueEmail("missing-sub"), true, "Missing", "Subject"),
                challengeId(uniquePhone()),
                null,
                null
        )).isInstanceOf(GoogleAuthenticationException.class);

        String expiredPhone = uniquePhone();
        UUID expiredChallengeId = challengeId(expiredPhone);
        ChannelLinkChallenge expired = channelLinkChallengeRepository.findById(expiredChallengeId).orElseThrow();
        expired.setExpiresAt(Instant.now().minusSeconds(1));
        channelLinkChallengeRepository.save(expired);

        assertThatThrownBy(() -> googleFederationService.authenticate(
                googleUser("google-sub-expired", uniqueEmail("expired"), true, "Expired", "User"),
                expiredChallengeId,
                null,
                null
        )).isInstanceOf(GoogleAuthenticationException.class);

        String reusedPhone = uniquePhone();
        UUID reusedChallengeId = challengeId(reusedPhone);
        googleFederationService.authenticate(
                googleUser("google-sub-reused-first", uniqueEmail("reused-first"), true, "First", "User"),
                reusedChallengeId,
                null,
                null
        );

        assertThatThrownBy(() -> googleFederationService.authenticate(
                googleUser("google-sub-reused-second", uniqueEmail("reused-second"), true, "Second", "User"),
                reusedChallengeId,
                null,
                null
        )).isInstanceOf(GoogleAuthenticationException.class);
    }

    @Test
    void googleRejectsConflictsAndUnavailableAccounts() {
        String emailConflict = uniqueEmail("email-conflict");
        localUser(emailConflict, uniquePhone(), true);

        assertThatThrownBy(() -> googleFederationService.authenticate(
                googleUser("google-sub-email-conflict", emailConflict, true, "Email", "Conflict"),
                challengeId(uniquePhone()),
                null,
                null
        )).isInstanceOf(GoogleAuthenticationException.class);

        String phoneConflict = uniquePhone();
        localUser(uniqueEmail("phone-owner"), phoneConflict, true);
        assertThatThrownBy(() -> googleFederationService.authenticate(
                googleUser("google-sub-phone-conflict", uniqueEmail("phone-conflict"), true, "Phone", "Conflict"),
                challengeId(phoneConflict),
                null,
                null
        )).isInstanceOf(GoogleAuthenticationException.class);

        String disabledEmail = uniqueEmail("disabled-google");
        UserAccount disabled = localUser(disabledEmail, uniquePhone(), true);
        disabled.setEnabled(false);
        userRepository.save(disabled);
        linkGoogleIdentity(disabled, "google-sub-disabled");
        assertThatThrownBy(() -> googleFederationService.authenticate(
                googleUser("google-sub-disabled", disabledEmail, true, "Disabled", "User"),
                null,
                null,
                null
        )).isInstanceOf(GoogleAuthenticationException.class);

        String lockedEmail = uniqueEmail("locked-google");
        UserAccount locked = localUser(lockedEmail, uniquePhone(), true);
        locked.setAccountNonLocked(false);
        userRepository.save(locked);
        linkGoogleIdentity(locked, "google-sub-locked");
        assertThatThrownBy(() -> googleFederationService.authenticate(
                googleUser("google-sub-locked", lockedEmail, true, "Locked", "User"),
                null,
                null,
                null
        )).isInstanceOf(GoogleAuthenticationException.class);

        String deletedEmail = uniqueEmail("deleted-google");
        UserAccount deleted = localUser(deletedEmail, uniquePhone(), true);
        deleted.setDeleted(true);
        deleted.setEnabled(false);
        userRepository.save(deleted);
        linkGoogleIdentity(deleted, "google-sub-deleted");
        assertThatThrownBy(() -> googleFederationService.authenticate(
                googleUser("google-sub-deleted", deletedEmail, true, "Deleted", "User"),
                null,
                null,
                null
        )).isInstanceOf(GoogleAuthenticationException.class);
    }

    @Test
    void googleOnlyUserCannotUsePasswordLoginAndExistingPasswordLoginStillWorks() throws Exception {
        String googleEmail = uniqueEmail("google-password-disabled");
        googleFederationService.authenticate(
                googleUser("google-sub-password-disabled", googleEmail, true, "Google", "Only"),
                challengeId(uniquePhone()),
                null,
                null
        );

        mockMvc.perform(post("/login")
                        .with(csrf())
                        .param("username", googleEmail)
                        .param("password", PASSWORD))
                .andExpect(status().is3xxRedirection())
                .andExpect(header().string(HttpHeaders.LOCATION, "/login?error"));

        String passwordEmail = uniqueEmail("password-still-works");
        localUser(passwordEmail, uniquePhone(), false);
        mockMvc.perform(post("/login")
                        .with(csrf())
                        .param("username", passwordEmail)
                        .param("password", PASSWORD))
                .andExpect(status().is3xxRedirection())
                .andExpect(header().string(HttpHeaders.LOCATION, "/login/verify"));
    }

    private String n8nServiceAccessToken(String scope) throws Exception {
        MvcResult result = mockMvc.perform(post("/oauth2/token")
                        .with(httpBasic(N8N_CLIENT_ID, N8N_CLIENT_SECRET))
                        .param(OAuth2ParameterNames.GRANT_TYPE, "client_credentials")
                        .param(OAuth2ParameterNames.SCOPE, scope))
                .andExpect(status().isOk())
                .andReturn();

        return nestedString(result, "access_token");
    }

    private String createChallengeUrl(String phoneNumber) {
        return channelLinkChallengeService.createWhatsappChallenge(
                new CreateChannelLinkChallengeRequest(phoneNumber, null),
                N8N_CLIENT_ID,
                null,
                null
        ).registrationUrl();
    }

    private MockHttpSession startChannelSession(String registrationUrl) throws Exception {
        MockHttpServletRequestBuilder startRequest = get("/api/v1/auth/channel/start")
                .param("linkToken", queryParam(registrationUrl, "linkToken"));
        String authMode = queryParam(registrationUrl, "authMode");
        if (authMode != null) {
            startRequest.param("authMode", authMode);
        }

        MvcResult start = mockMvc.perform(startRequest)
                .andExpect(status().is3xxRedirection())
                .andReturn();

        assertThat(start.getRequest().getSession(false)).isInstanceOf(MockHttpSession.class);
        return (MockHttpSession) start.getRequest().getSession(false);
    }

    private UUID challengeId(String phoneNumber) {
        CreateChannelLinkChallengeResponse response = channelLinkChallengeService.createWhatsappChallenge(
                new CreateChannelLinkChallengeRequest(phoneNumber, null),
                N8N_CLIENT_ID,
                null,
                null
        );
        String linkToken = queryParam(response.registrationUrl(), "linkToken");
        return channelLinkChallengeService.resolveForStart(linkToken, null, null).orElseThrow();
    }

    private UserAccount localUser(String email, String phoneNumber, boolean emailVerified) {
        UserAccount user = new UserAccount();
        user.setFirstName("Local");
        user.setLastName("User");
        user.setEmail(email);
        user.setPassword(passwordEncoder.encode(PASSWORD));
        user.setPasswordLoginEnabled(true);
        user.setPhoneNumber(phoneNumber);
        user.setEmailVerified(emailVerified);
        user.setRoleId(roleRepository.findByName(RoleNames.TRAVELLER).orElseThrow().getId());
        return userRepository.save(user);
    }

    private void linkGoogleIdentity(UserAccount account, String subject) {
        com.NgariTech.identity_service.auth.google.ExternalIdentity identity =
                new com.NgariTech.identity_service.auth.google.ExternalIdentity();
        identity.setUserId(account.getId());
        identity.setProvider(ExternalIdentityProvider.GOOGLE);
        identity.setProviderSubject(subject);
        identity.setProviderEmail(account.getEmail());
        externalIdentityRepository.save(identity);
    }

    private OidcUser googleUser(
            String subject,
            String email,
            boolean emailVerified,
            String firstName,
            String lastName
    ) {
        Map<String, Object> claims = new HashMap<>();
        if (subject != null) {
            claims.put(StandardClaimNames.SUB, subject);
        }
        claims.put(StandardClaimNames.EMAIL, email);
        claims.put(StandardClaimNames.EMAIL_VERIFIED, emailVerified);
        claims.put(StandardClaimNames.GIVEN_NAME, firstName);
        claims.put(StandardClaimNames.FAMILY_NAME, lastName);
        claims.put(StandardClaimNames.PICTURE, "https://example.com/avatar.png");

        OidcIdToken idToken = new OidcIdToken(
                "test-id-token",
                Instant.now(),
                Instant.now().plusSeconds(300),
                claims
        );

        return new DefaultOidcUser(
                List.of(new SimpleGrantedAuthority("OIDC_USER")),
                idToken,
                subject == null ? StandardClaimNames.EMAIL : StandardClaimNames.SUB
        );
    }

    private String nestedString(MvcResult result, String... path) throws Exception {
        Map<String, Object> body = objectMapper.readValue(
                result.getResponse().getContentAsString(),
                new TypeReference<>() {
                }
        );

        Object current = body;
        for (String key : path) {
            if (current instanceof Map<?, ?> map) {
                current = map.get(key);
            }
        }

        return current == null ? null : current.toString();
    }

    private String queryParam(String location, String name) {
        return UriComponentsBuilder.fromUriString(location).build().getQueryParams().getFirst(name);
    }

    private String uniqueEmail(String prefix) {
        return prefix + "-" + UUID.randomUUID() + "@example.com";
    }

    private String uniquePhone() {
        return "2547" + String.format(Locale.ROOT, "%08d", Math.abs(UUID.randomUUID().getMostSignificantBits() % 100_000_000L));
    }
}
