package com.NgariTech.identity_service.config;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;

@Getter
@Setter
@ConfigurationProperties(prefix = "iam.oauth2")
public class IamOAuth2ClientProperties {

    private Token token = new Token();
    private Clients clients = new Clients();

    @Getter
    @Setter
    public static class Token {
        private long accessTokenMinutes = 10;
        private long authorizationCodeMinutes = 5;
        private long refreshTokenDays = 7;
    }

    @Getter
    @Setter
    public static class Clients {
        private BrowserClient travelWeb = new BrowserClient();
        private ServiceClient n8nOrchestrator = new ServiceClient();
    }

    @Getter
    @Setter
    public static class BrowserClient {
        private String clientId = "travel-web-bff";
        private String clientSecret = "travel-web-dev-secret";
        private String redirectUris = "http://127.0.0.1:8082/login/oauth2/code/iam";
        private String postLogoutRedirectUris = "http://127.0.0.1:8082/";
        private String scopes = "openid,profile,email,phone,travel.read,travel.write,payment:create,payment:read,menu:read";
        private boolean requireProofKey = true;
        private boolean requireAuthorizationConsent = false;
    }

    @Getter
    @Setter
    public static class ServiceClient {
        private String clientId = "n8n-orchestrator";
        private String clientSecret = "n8n-dev-secret";
        private String scopes = "service:n8n,channel_auth:create,travel.create,payment:read,menu:read";
    }
}
