package com.NgariTech.identity_service.auth.oidc;

import com.NgariTech.identity_service.role.Permission;
import com.NgariTech.identity_service.role.PermissionIdCodec;
import com.NgariTech.identity_service.role.PermissionRepository;
import com.NgariTech.identity_service.role.Role;
import com.NgariTech.identity_service.role.RoleRepository;
import com.NgariTech.identity_service.user.UserAccount;
import com.NgariTech.identity_service.user.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.oidc.StandardClaimNames;
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.LinkedHashMap;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class IamTokenClaimService {

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PermissionRepository permissionRepository;

    @Value("${security.jwt.audience}")
    private String audience;

    @Transactional(readOnly = true)
    public void customize(JwtEncodingContext context) {
        if (OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType())) {
            customizeAccessToken(context);
        }
        else if (OidcParameterNames.ID_TOKEN.equals(context.getTokenType().getValue())) {
            findUser(context.getPrincipal().getName()).ifPresent(account ->
                    identityClaims(account).forEach((name, value) -> context.getClaims().claim(name, value))
            );
        }
    }

    @Transactional(readOnly = true)
    public Optional<UserAccount> findUser(String principalName) {
        if (principalName == null || principalName.isBlank()) {
            return Optional.empty();
        }

        try {
            return userRepository.findByIdAndDeletedFalse(UUID.fromString(principalName.trim()));
        }
        catch (IllegalArgumentException exception) {
            return userRepository.findByEmailIgnoreCaseAndDeletedFalse(principalName.trim());
        }
    }

    @Transactional(readOnly = true)
    public List<String> roleNames(UserAccount account) {
        return roleRepository.findById(account.getRoleId())
                .map(role -> mutableList(role.getName()))
                .orElseGet(ArrayList::new);
    }

    @Transactional(readOnly = true)
    public List<String> permissionNames(UserAccount account) {
        return roleRepository.findById(account.getRoleId())
                .map(this::permissionNames)
                .orElseGet(ArrayList::new);
    }

    public Map<String, Object> identityClaims(UserAccount account) {
        Map<String, Object> claims = new LinkedHashMap<>();
        claims.put(StandardClaimNames.SUB, account.getId().toString());
        claims.put(StandardClaimNames.GIVEN_NAME, account.getFirstName());
        claims.put(StandardClaimNames.FAMILY_NAME, account.getLastName());
        claims.put(StandardClaimNames.NAME, account.getFirstName() + " " + account.getLastName());
        claims.put(StandardClaimNames.PREFERRED_USERNAME, account.getEmail());
        claims.put(StandardClaimNames.EMAIL, account.getEmail());
        claims.put(StandardClaimNames.EMAIL_VERIFIED, account.isEmailVerified());
        claims.put(StandardClaimNames.PHONE_NUMBER, account.getPhoneNumber());
        claims.put(StandardClaimNames.PHONE_NUMBER_VERIFIED, false);

        return claims;
    }

    private void customizeAccessToken(JwtEncodingContext context) {
        context.getClaims().audience(mutableList(audience));

        if (AuthorizationGrantType.CLIENT_CREDENTIALS.equals(context.getAuthorizationGrantType())) {
            context.getClaims()
                    .claim("client_id", context.getRegisteredClient().getClientId())
                    .claim("roles", mutableList("SERVICE"))
                    .claim("permissions", new ArrayList<>(context.getAuthorizedScopes().stream().sorted().toList()));
            return;
        }

        findUser(context.getPrincipal().getName()).ifPresent(account -> {
            context.getClaims()
                    .subject(account.getId().toString())
                    .claim("user_id", account.getId().toString())
                    .claim("roles", roleNames(account))
                    .claim("permissions", permissionNames(account));
            identityClaims(account).forEach((name, value) ->
                    context.getClaims().claim(name, value)
            );
        });
    }

    private List<String> permissionNames(Role role) {
        Set<String> permissionIds = PermissionIdCodec.parse(role.getPermissionIds());
        if (permissionIds.isEmpty()) {
            return new ArrayList<>();
        }

        return new ArrayList<>(permissionRepository.findByIdInOrderByNameAsc(permissionIds)
                .stream()
                .map(Permission::getName)
                .sorted()
                .toList());
    }

    private List<String> mutableList(String value) {
        List<String> values = new ArrayList<>();
        values.add(value);
        return values;
    }
}
