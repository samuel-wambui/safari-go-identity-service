package com.NgariTech.identity_service.auth.google;

import org.springframework.security.oauth2.core.oidc.StandardClaimNames;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;

import java.util.Map;

public record GoogleProfile(
        String subject,
        String email,
        boolean emailVerified,
        String firstName,
        String lastName,
        String picture
) {

    public static GoogleProfile from(OidcUser user) {
        Map<String, Object> claims = user.getClaims();
        return new GoogleProfile(
                asString(claims.get(StandardClaimNames.SUB)),
                normalizeEmail(asString(claims.get(StandardClaimNames.EMAIL))),
                Boolean.TRUE.equals(claims.get(StandardClaimNames.EMAIL_VERIFIED)),
                asString(claims.get(StandardClaimNames.GIVEN_NAME)),
                asString(claims.get(StandardClaimNames.FAMILY_NAME)),
                asString(claims.get(StandardClaimNames.PICTURE))
        );
    }

    private static String normalizeEmail(String email) {
        return email == null ? null : email.trim().toLowerCase();
    }

    private static String asString(Object value) {
        if (value == null) {
            return null;
        }

        String text = value.toString().trim();
        return text.isBlank() ? null : text;
    }
}
