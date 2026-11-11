package com.NgariTech.identity_service.auth.oidc;

import com.NgariTech.identity_service.config.IamOAuth2ClientProperties;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.Set;
import java.util.UUID;

@Component
@RequiredArgsConstructor
public class OAuth2ClientSeeder implements ApplicationRunner {

    private final RegisteredClientRepository registeredClientRepository;
    private final PasswordEncoder passwordEncoder;
    private final IamOAuth2ClientProperties properties;

    @Override
    public void run(ApplicationArguments args) {
        saveTravelWebClient();
        saveN8nClient();
    }

    private void saveTravelWebClient() {
        IamOAuth2ClientProperties.BrowserClient client = properties.getClients().getTravelWeb();
        RegisteredClient existing = registeredClientRepository.findByClientId(client.getClientId());

        RegisteredClient.Builder builder = RegisteredClient.withId(existing == null ? UUID.randomUUID().toString() : existing.getId())
                .clientId(client.getClientId())
                .clientIdIssuedAt(existing == null ? Instant.now() : existing.getClientIdIssuedAt())
                .clientName("Travel Web BFF")
                .clientSecret(passwordEncoder.encode(requiredSecret(client.getClientSecret(), "travel web client")))
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .scopes(scopes -> {
                    scopes.clear();
                    scopes.addAll(csv(client.getScopes()));
                    scopes.add(OidcScopes.OPENID);
                })
                .redirectUris(redirectUris -> {
                    redirectUris.clear();
                    redirectUris.addAll(csv(client.getRedirectUris()));
                })
                .postLogoutRedirectUris(postLogoutRedirectUris -> {
                    postLogoutRedirectUris.clear();
                    postLogoutRedirectUris.addAll(csv(client.getPostLogoutRedirectUris()));
                })
                .clientSettings(ClientSettings.builder()
                        .requireProofKey(client.isRequireProofKey())
                        .requireAuthorizationConsent(client.isRequireAuthorizationConsent())
                        .build())
                .tokenSettings(tokenSettings());

        registeredClientRepository.save(builder.build());
    }

    private void saveN8nClient() {
        IamOAuth2ClientProperties.ServiceClient client = properties.getClients().getN8nOrchestrator();
        RegisteredClient existing = registeredClientRepository.findByClientId(client.getClientId());

        RegisteredClient registeredClient = RegisteredClient.withId(existing == null ? UUID.randomUUID().toString() : existing.getId())
                .clientId(client.getClientId())
                .clientIdIssuedAt(existing == null ? Instant.now() : existing.getClientIdIssuedAt())
                .clientName("n8n Orchestrator")
                .clientSecret(passwordEncoder.encode(requiredSecret(client.getClientSecret(), "n8n client")))
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .scopes(scopes -> {
                    scopes.clear();
                    scopes.addAll(csv(client.getScopes()));
                })
                .clientSettings(ClientSettings.builder()
                        .requireProofKey(false)
                        .requireAuthorizationConsent(false)
                        .build())
                .tokenSettings(tokenSettings())
                .build();

        registeredClientRepository.save(registeredClient);
    }

    private TokenSettings tokenSettings() {
        IamOAuth2ClientProperties.Token token = properties.getToken();
        return TokenSettings.builder()
                .authorizationCodeTimeToLive(Duration.ofMinutes(token.getAuthorizationCodeMinutes()))
                .accessTokenTimeToLive(Duration.ofMinutes(token.getAccessTokenMinutes()))
                .refreshTokenTimeToLive(Duration.ofDays(token.getRefreshTokenDays()))
                .reuseRefreshTokens(false)
                .idTokenSignatureAlgorithm(SignatureAlgorithm.RS256)
                .build();
    }

    private Set<String> csv(String value) {
        Set<String> values = new LinkedHashSet<>();
        if (value == null || value.isBlank()) {
            return values;
        }

        Arrays.stream(value.split(","))
                .map(String::trim)
                .filter(item -> !item.isBlank())
                .forEach(values::add);

        return values;
    }

    private String requiredSecret(String secret, String clientName) {
        if (secret == null || secret.isBlank()) {
            throw new IllegalStateException("Missing secret for " + clientName);
        }

        return secret.trim();
    }
}
