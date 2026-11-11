package com.NgariTech.identity_service.auth.oidc;

import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.core.oidc.StandardClaimNames;
import org.springframework.security.oauth2.server.authorization.oidc.authentication.OidcUserInfoAuthenticationContext;
import org.springframework.stereotype.Service;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

@Service
@RequiredArgsConstructor
public class OidcUserInfoService {

    private final IamTokenClaimService tokenClaimService;

    public OidcUserInfo userInfo(OidcUserInfoAuthenticationContext context) {
        return tokenClaimService.findUser(context.getAuthorization().getPrincipalName())
                .map(account -> new OidcUserInfo(filterByScope(
                        tokenClaimService.identityClaims(account),
                        context.getAccessToken().getScopes()
                )))
                .orElseGet(() -> new OidcUserInfo(Map.of()));
    }

    private Map<String, Object> filterByScope(Map<String, Object> claims, Set<String> scopes) {
        Map<String, Object> filtered = new LinkedHashMap<>();
        filtered.put(StandardClaimNames.SUB, claims.get(StandardClaimNames.SUB));

        if (scopes.contains(OidcScopes.PROFILE)) {
            copy(claims, filtered, StandardClaimNames.NAME);
            copy(claims, filtered, StandardClaimNames.GIVEN_NAME);
            copy(claims, filtered, StandardClaimNames.FAMILY_NAME);
            copy(claims, filtered, StandardClaimNames.PREFERRED_USERNAME);
            copy(claims, filtered, StandardClaimNames.UPDATED_AT);
        }

        if (scopes.contains(OidcScopes.EMAIL)) {
            copy(claims, filtered, StandardClaimNames.EMAIL);
            copy(claims, filtered, StandardClaimNames.EMAIL_VERIFIED);
        }

        if (scopes.contains(OidcScopes.PHONE)) {
            copy(claims, filtered, StandardClaimNames.PHONE_NUMBER);
            copy(claims, filtered, StandardClaimNames.PHONE_NUMBER_VERIFIED);
        }

        return filtered;
    }

    private void copy(Map<String, Object> source, Map<String, Object> target, String claim) {
        if (source.containsKey(claim)) {
            target.put(claim, source.get(claim));
        }
    }
}
