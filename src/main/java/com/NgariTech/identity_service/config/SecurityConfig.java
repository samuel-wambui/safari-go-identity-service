package com.NgariTech.identity_service.config;

import com.NgariTech.identity_service.auth.oidc.IamTokenClaimService;
import com.NgariTech.identity_service.auth.oidc.OAuth2EndpointAuditHandlers;
import com.NgariTech.identity_service.auth.oidc.OidcUserInfoService;
import com.NgariTech.identity_service.auth.oidc.RefreshTokenHashingAuthorizationService;
import com.NgariTech.identity_service.auth.google.GoogleOAuth2FailureHandler;
import com.NgariTech.identity_service.auth.google.GoogleOAuth2SuccessHandler;
import com.NgariTech.identity_service.auth.google.GoogleOidcUserService;
import com.NgariTech.identity_service.auth.google.NoOpOAuth2AuthorizedClientRepository;
import com.NgariTech.identity_service.common.api.ApiCode;
import com.NgariTech.identity_service.common.api.ApiResponse;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.security.config.Customizer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.authorization.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import tools.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

@Configuration
@EnableMethodSecurity
@EnableConfigurationProperties(IamOAuth2ClientProperties.class)
public class SecurityConfig {

	@Bean
	@Order(Ordered.HIGHEST_PRECEDENCE)
	SecurityFilterChain authorizationServerSecurityFilterChain(
			HttpSecurity http,
			RegisteredClientRepository registeredClientRepository,
			OAuth2AuthorizationService authorizationService,
			OAuth2AuthorizationConsentService authorizationConsentService,
			AuthorizationServerSettings authorizationServerSettings,
			OidcUserInfoService oidcUserInfoService,
			OAuth2EndpointAuditHandlers oauth2EndpointAuditHandlers
	) throws Exception {
		OAuth2AuthorizationServerConfigurer authorizationServerConfigurer = new OAuth2AuthorizationServerConfigurer();
		RequestMatcher authorizationServerEndpoints = authorizationServerConfigurer.getEndpointsMatcher();

			return http
					.securityMatcher(authorizationServerEndpoints)
					.cors(Customizer.withDefaults())
					.with(authorizationServerConfigurer, authorizationServer -> authorizationServer
							.registeredClientRepository(registeredClientRepository)
						.authorizationService(authorizationService)
						.authorizationConsentService(authorizationConsentService)
						.authorizationServerSettings(authorizationServerSettings)
						.tokenEndpoint(token -> token
								.accessTokenResponseHandler(oauth2EndpointAuditHandlers::onTokenSuccess)
								.errorResponseHandler(oauth2EndpointAuditHandlers::onTokenFailure)
						)
						.tokenRevocationEndpoint(revocation -> revocation
								.revocationResponseHandler(oauth2EndpointAuditHandlers::onRevocationSuccess)
								.errorResponseHandler(oauth2EndpointAuditHandlers::onRevocationFailure)
						)
						.oidc(oidc -> oidc.userInfoEndpoint(userInfo ->
								userInfo.userInfoMapper(oidcUserInfoService::userInfo)
						))
				)
				.authorizeHttpRequests(authorize -> authorize.anyRequest().authenticated())
				.exceptionHandling(exceptions -> exceptions.defaultAuthenticationEntryPointFor(
						new LoginUrlAuthenticationEntryPoint("/login"),
						new MediaTypeRequestMatcher(MediaType.TEXT_HTML)
				))
				.csrf(csrf -> csrf.ignoringRequestMatchers(authorizationServerEndpoints))
				.build();
	}

	@Bean
	@Order(1)
	SecurityFilterChain googleLoginSecurityFilterChain(
			HttpSecurity http,
			GoogleOidcUserService googleOidcUserService,
			GoogleOAuth2SuccessHandler googleOAuth2SuccessHandler,
			GoogleOAuth2FailureHandler googleOAuth2FailureHandler,
			OAuth2AuthorizedClientRepository authorizedClientRepository
	) throws Exception {
		RequestMatcher googleLoginEndpoints = new OrRequestMatcher(
				PathPatternRequestMatcher.pathPattern("/api/v1/auth/channel/**"),
				PathPatternRequestMatcher.pathPattern("/api/v1/auth/google/**"),
				PathPatternRequestMatcher.pathPattern("/api/v1/mobile/auth/google/start"),
				PathPatternRequestMatcher.pathPattern("/oauth2/authorization/**"),
				PathPatternRequestMatcher.pathPattern("/login/oauth2/code/**")
		);

			return http
					.securityMatcher(googleLoginEndpoints)
					.cors(Customizer.withDefaults())
					.sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED))
					.authorizeHttpRequests(authorize -> authorize.anyRequest().permitAll())
				.oauth2Login(oauth2 -> oauth2
						.authorizedClientRepository(authorizedClientRepository)
						.userInfoEndpoint(userInfo -> userInfo.oidcUserService(googleOidcUserService))
						.successHandler(googleOAuth2SuccessHandler)
						.failureHandler(googleOAuth2FailureHandler)
				)
				.build();
	}

	@Bean
	@Order(2)
	SecurityFilterChain apiSecurityFilterChain(
			HttpSecurity http,
			@Qualifier("resourceServerJwtDecoder") JwtDecoder resourceServerJwtDecoder,
			JwtAuthenticationConverter jwtAuthenticationConverter,
			ObjectMapper objectMapper
	) throws Exception {
		RequestMatcher apiEndpoints = new OrRequestMatcher(
				PathPatternRequestMatcher.pathPattern("/api/**"),
				PathPatternRequestMatcher.pathPattern("/actuator/health")
		);

			return http
					.securityMatcher(apiEndpoints)
					.cors(Customizer.withDefaults())
					.csrf(AbstractHttpConfigurer::disable)
					.sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
				.authorizeHttpRequests(authorize -> authorize
						.requestMatchers(HttpMethod.POST, "/api/v1/users/register").permitAll()
						.requestMatchers(HttpMethod.POST, "/api/v1/mobile/auth/login").permitAll()
						.requestMatchers(HttpMethod.POST, "/api/v1/mobile/auth/google/exchange").permitAll()
						.requestMatchers("/actuator/health").permitAll()
						.requestMatchers(HttpMethod.POST, "/api/v1/whatsapp/auth/challenges")
						.hasAnyAuthority("channel_auth:create", "service:n8n")
						.requestMatchers(HttpMethod.POST, "/api/v1/whatsapp/auth/tokens")
						.hasAuthority("service:n8n")
						.requestMatchers(HttpMethod.GET, "/api/v1/whatsapp/auth/status")
						.hasAuthority("service:n8n")
						.requestMatchers(HttpMethod.POST, "/api/v1/auth/logout")
						.hasAnyAuthority("service:n8n", "ROLE_ADMIN", "ROLE_SUPER_ADMIN")
						.requestMatchers(HttpMethod.GET, "/api/v1/users/**")
						.hasAnyAuthority("ROLE_ADMIN", "ROLE_SUPER_ADMIN", "user:read")
						.requestMatchers("/api/v1/roles/**", "/api/v1/permissions/**")
						.hasAnyAuthority("ROLE_ADMIN", "ROLE_SUPER_ADMIN", "role:assign")
						.anyRequest().authenticated()
				)
				.oauth2ResourceServer(oauth2 -> oauth2.jwt(jwt -> jwt
						.decoder(resourceServerJwtDecoder)
						.jwtAuthenticationConverter(jwtAuthenticationConverter)
				))
				.exceptionHandling(exceptions -> exceptions
						.defaultAuthenticationEntryPointFor(
								apiAuthenticationEntryPoint(objectMapper),
								PathPatternRequestMatcher.pathPattern("/api/**")
						)
						.defaultAccessDeniedHandlerFor(
								apiAccessDeniedHandler(objectMapper),
								PathPatternRequestMatcher.pathPattern("/api/**")
						)
				)
				.httpBasic(AbstractHttpConfigurer::disable)
				.build();
	}

	@Bean
	@Order(3)
	SecurityFilterChain browserLoginSecurityFilterChain(HttpSecurity http) throws Exception {
		return http
					.cors(Customizer.withDefaults())
						.authorizeHttpRequests(authorize -> authorize
								.requestMatchers(
									"/login",
									"/login/verify",
									"/register",
									"/forgot-password",
									"/reset-password",
									"/css/**",
								"/js/**",
								"/images/**",
								"/favicon.ico"
						).permitAll()
						.anyRequest().authenticated()
				)
					.formLogin(AbstractHttpConfigurer::disable)
				.logout(logout -> logout
						.logoutSuccessUrl("/login?logout")
						.permitAll()
				)
					.build();
	}

	@Bean
	CorsConfigurationSource corsConfigurationSource() {
		CorsConfiguration configuration = new CorsConfiguration();
		configuration.setAllowedOriginPatterns(List.of("*"));
		configuration.setAllowedMethods(List.of("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"));
		configuration.setAllowedHeaders(List.of("*"));
		configuration.setExposedHeaders(List.of("Location"));
		configuration.setAllowCredentials(false);
		configuration.setMaxAge(3600L);

		UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
		source.registerCorsConfiguration("/**", configuration);
		return source;
	}

	@Bean
	RegisteredClientRepository registeredClientRepository(JdbcTemplate jdbcTemplate) {
		return new JdbcRegisteredClientRepository(jdbcTemplate);
	}

	@Bean
	OAuth2AuthorizationService authorizationService(
			JdbcTemplate jdbcTemplate,
			RegisteredClientRepository registeredClientRepository,
			com.NgariTech.identity_service.auth.AuditLogService auditLogService
	) {
		return new RefreshTokenHashingAuthorizationService(jdbcTemplate, registeredClientRepository, auditLogService);
	}

	@Bean
	OAuth2AuthorizationConsentService authorizationConsentService(
			JdbcTemplate jdbcTemplate,
			RegisteredClientRepository registeredClientRepository
	) {
		return new JdbcOAuth2AuthorizationConsentService(jdbcTemplate, registeredClientRepository);
	}

	@Bean
	OAuth2AuthorizedClientRepository oauth2AuthorizedClientRepository() {
		return new NoOpOAuth2AuthorizedClientRepository();
	}

	@Bean
	AuthorizationServerSettings authorizationServerSettings(@Value("${security.jwt.issuer}") String issuer) {
		return AuthorizationServerSettings.builder()
				.issuer(issuer)
				.build();
	}

	@Bean
	@Primary
	JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
		return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
	}

	@Bean
	JwtDecoder resourceServerJwtDecoder(
			RSAKey rsaKey,
			@Value("${security.jwt.issuer}") String issuer,
			@Value("${security.jwt.audience}") String audience
	) throws JOSEException {
		NimbusJwtDecoder jwtDecoder = NimbusJwtDecoder
				.withPublicKey(rsaKey.toRSAPublicKey())
				.signatureAlgorithm(SignatureAlgorithm.RS256)
				.build();

		OAuth2TokenValidator<Jwt> issuerValidator = JwtValidators.createDefaultWithIssuer(issuer);
		OAuth2TokenValidator<Jwt> audienceValidator = jwt -> jwt.getAudience().contains(audience)
				? OAuth2TokenValidatorResult.success()
				: OAuth2TokenValidatorResult.failure(new OAuth2Error(
				OAuth2ErrorCodes.INVALID_TOKEN,
				"Missing required audience",
				null
		));

		jwtDecoder.setJwtValidator(new DelegatingOAuth2TokenValidator<>(issuerValidator, audienceValidator));
		return jwtDecoder;
	}

	@Bean
	OAuth2TokenCustomizer<JwtEncodingContext> jwtCustomizer(
			IamTokenClaimService tokenClaimService,
			@Value("${security.jwt.key-id}") String keyId
	) {
		return context -> {
			context.getJwsHeader().keyId(keyId);
			tokenClaimService.customize(context);
		};
	}

	@Bean
	JwtAuthenticationConverter jwtAuthenticationConverter() {
		JwtGrantedAuthoritiesConverter scopeAuthoritiesConverter = new JwtGrantedAuthoritiesConverter();
		JwtAuthenticationConverter converter = new JwtAuthenticationConverter();
		converter.setPrincipalClaimName("sub");
		converter.setJwtGrantedAuthoritiesConverter(jwt -> {
			Set<GrantedAuthority> authorities = new LinkedHashSet<>();
			Collection<GrantedAuthority> scopeAuthorities = scopeAuthoritiesConverter.convert(jwt);
			if (scopeAuthorities != null) {
				authorities.addAll(scopeAuthorities);
			}

			claimAsList(jwt.getClaim("roles")).forEach(role ->
					authorities.add(new SimpleGrantedAuthority("ROLE_" + role))
			);

			claimAsList(jwt.getClaim("permissions")).forEach(permission ->
					authorities.add(new SimpleGrantedAuthority(permission))
			);

			return authorities;
		});

		return converter;
	}

	private List<String> claimAsList(Object claim) {
		if (claim instanceof Collection<?> values) {
			return values.stream()
					.filter(String.class::isInstance)
					.map(String.class::cast)
					.toList();
		}

		if (claim instanceof String value && !value.isBlank()) {
			return List.of(value);
		}

		return List.of();
	}

	private AuthenticationEntryPoint apiAuthenticationEntryPoint(ObjectMapper objectMapper) {
		return (request, response, exception) -> writeApiError(
				response,
				objectMapper,
				HttpServletResponse.SC_UNAUTHORIZED,
				"Authentication is required",
				ApiCode.UNAUTHORIZED
		);
	}

	private AccessDeniedHandler apiAccessDeniedHandler(ObjectMapper objectMapper) {
		return (request, response, exception) -> writeApiError(
				response,
				objectMapper,
				HttpServletResponse.SC_FORBIDDEN,
				"Access is denied",
				ApiCode.FORBIDDEN
		);
	}

	private void writeApiError(
			HttpServletResponse response,
			ObjectMapper objectMapper,
			int status,
			String message,
			String code
	) throws IOException {
		response.setStatus(status);
		response.setContentType(MediaType.APPLICATION_JSON_VALUE);
		objectMapper.writeValue(response.getOutputStream(), ApiResponse.failure(message, code, null));
	}
}
