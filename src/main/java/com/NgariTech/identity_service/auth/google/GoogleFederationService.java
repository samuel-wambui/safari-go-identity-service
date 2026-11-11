package com.NgariTech.identity_service.auth.google;

import com.NgariTech.identity_service.auth.AuditEventType;
import com.NgariTech.identity_service.auth.AuditLogService;
import com.NgariTech.identity_service.auth.LoginAttemptService;
import com.NgariTech.identity_service.auth.channel.ChannelAuthenticationService;
import com.NgariTech.identity_service.auth.channel.ChannelLinkChallenge;
import com.NgariTech.identity_service.auth.channel.ChannelLinkChallengeException;
import com.NgariTech.identity_service.auth.channel.ChannelLinkChallengeService;
import com.NgariTech.identity_service.role.Role;
import com.NgariTech.identity_service.role.RoleNames;
import com.NgariTech.identity_service.role.RoleRepository;
import com.NgariTech.identity_service.user.UserAccount;
import com.NgariTech.identity_service.user.UserRepository;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;
import java.util.Locale;
import java.util.Optional;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class GoogleFederationService {

    private static final Logger log = LoggerFactory.getLogger(GoogleFederationService.class);
    private static final int UNUSABLE_PASSWORD_BYTES = 32;

    private final ExternalIdentityRepository externalIdentityRepository;
    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;
    private final ChannelLinkChallengeService channelLinkChallengeService;
    private final ChannelAuthenticationService channelAuthenticationService;
    private final LoginAttemptService loginAttemptService;
    private final AuditLogService auditLogService;
    private final SecureRandom secureRandom = new SecureRandom();

    @Transactional
    public UserAccount authenticate(
            OidcUser oidcUser,
            UUID channelLinkChallengeId,
            String sourceIp,
            String userAgent
    ) {
        return authenticate(oidcUser, channelLinkChallengeId, false, sourceIp, userAgent);
    }

    @Transactional
    public UserAccount authenticateMobile(
            OidcUser oidcUser,
            UUID channelLinkChallengeId,
            String sourceIp,
            String userAgent
    ) {
        return authenticate(oidcUser, channelLinkChallengeId, true, sourceIp, userAgent);
    }

    private UserAccount authenticate(
            OidcUser oidcUser,
            UUID channelLinkChallengeId,
            boolean allowVerifiedEmailLinking,
            String sourceIp,
            String userAgent
    ) {
        GoogleProfile profile = GoogleProfile.from(oidcUser);
        validateProfile(profile, sourceIp, userAgent);

        Optional<ExternalIdentity> existingIdentity = externalIdentityRepository
                .findByProviderAndProviderSubject(ExternalIdentityProvider.GOOGLE, profile.subject());

        if (existingIdentity.isPresent()) {
            return authenticateLinkedIdentity(existingIdentity.get(), profile, channelLinkChallengeId, sourceIp, userAgent);
        }

        if (channelLinkChallengeId == null) {
            if (allowVerifiedEmailLinking) {
                return linkExistingVerifiedEmailAccount(profile, sourceIp, userAgent);
            }
            recordFailure(profile.email(), sourceIp, userAgent, "Google account is not linked to IAM user");
            throw new GoogleAuthenticationException("Google account is not linked to IAM user");
        }

        ChannelLinkChallenge challenge = requireChallenge(
                channelLinkChallengeId,
                sourceIp,
                userAgent
        );

        UserAccount account = userRepository.findByPhoneNumberAndDeletedFalse(challenge.getPhoneNumber())
                .orElseGet(() -> userRepository.findByNormalizedPhoneNumberAndDeletedFalse(challenge.getPhoneNumber())
                        .orElse(null));

        if (account != null) {
            return linkExistingPhoneAccount(account, profile, challenge, sourceIp, userAgent);
        }

        if (userRepository.findByEmailIgnoreCase(profile.email()).isPresent()) {
            recordConflict(profile.email(), sourceIp, userAgent, "Google email already belongs to another IAM user");
            throw new GoogleAuthenticationException("Account linking is required");
        }

        return registerTraveller(profile, challenge, sourceIp, userAgent);
    }

    private UserAccount linkExistingVerifiedEmailAccount(
            GoogleProfile profile,
            String sourceIp,
            String userAgent
    ) {
        UserAccount account = userRepository.findByEmailIgnoreCaseAndDeletedFalse(profile.email())
                .orElseThrow(() -> {
                    recordFailure(profile.email(), sourceIp, userAgent, "Google email does not match a registered IAM user");
                    return new GoogleAuthenticationException("Google email does not match a registered IAM user");
                });

        account = refreshExpiredLock(account, sourceIp, userAgent);
        ensureAccountAvailable(account, sourceIp, userAgent);

        if (!account.isEmailVerified()) {
            recordConflict(account.getEmail(), sourceIp, userAgent, "Google email matches an unverified IAM account");
            throw new GoogleAuthenticationException("IAM email is not verified");
        }

        if (externalIdentityRepository.findByUserIdAndProvider(account.getId(), ExternalIdentityProvider.GOOGLE).isPresent()) {
            recordConflict(account.getEmail(), sourceIp, userAgent, "IAM user is already linked to another Google subject");
            throw new GoogleAuthenticationException("IAM user is already linked to another Google account");
        }

        Instant now = Instant.now();
        ExternalIdentity identity = new ExternalIdentity();
        identity.setProvider(ExternalIdentityProvider.GOOGLE);
        identity.setProviderSubject(profile.subject());
        identity.setProviderEmail(profile.email());
        identity.setUserId(account.getId());
        identity.setLastLoginAt(now);
        externalIdentityRepository.save(identity);
        markGoogleLogin(account, now);

        log.info(
                "mobile.google.email_link.success userId={} googleSubjectPresent={} emailVerified={}",
                account.getId(),
                profile.subject() != null,
                profile.emailVerified()
        );
        auditLogService.record(
                AuditEventType.GOOGLE_IDENTITY_LINKED,
                account.getId(),
                account.getEmail(),
                sourceIp,
                userAgent,
                "Google identity linked to registered IAM email for mobile login"
        );
        auditLogService.record(
                AuditEventType.GOOGLE_LOGIN_SUCCESS,
                account.getId(),
                account.getEmail(),
                sourceIp,
                userAgent,
                "Google login succeeded"
        );

        return account;
    }

    private UserAccount authenticateLinkedIdentity(
            ExternalIdentity identity,
            GoogleProfile profile,
            UUID channelLinkChallengeId,
            String sourceIp,
            String userAgent
    ) {
        UserAccount account = userRepository.findByIdAndDeletedFalse(identity.getUserId())
                .orElseThrow(() -> {
                    recordFailure(profile.email(), sourceIp, userAgent, "Linked IAM account is unavailable");
                    return new GoogleAuthenticationException("Invalid credentials or account unavailable");
                });

        account = refreshExpiredLock(account, sourceIp, userAgent);
        ensureAccountAvailable(account, sourceIp, userAgent);

        if (channelLinkChallengeId != null) {
            ChannelLinkChallenge challenge = requireChallenge(
                    channelLinkChallengeId,
                    sourceIp,
                    userAgent
            );
            if (!challenge.getPhoneNumber().equals(account.getPhoneNumber())) {
                recordConflict(account.getEmail(), sourceIp, userAgent, "Linked Google identity does not match WhatsApp phone owner");
                throw new GoogleAuthenticationException("Account linking is required");
            }
            channelLinkChallengeService.consumeLoaded(challenge);
            channelAuthenticationService.recordWhatsappAuthentication(account, challenge.getPhoneNumber(), sourceIp, userAgent);
        }

        Instant now = Instant.now();
        identity.setProviderEmail(profile.email());
        identity.setLastLoginAt(now);
        markGoogleLogin(account, now);

        auditLogService.record(
                AuditEventType.GOOGLE_LOGIN_SUCCESS,
                account.getId(),
                account.getEmail(),
                sourceIp,
                userAgent,
                "Google login succeeded"
        );

        return account;
    }

    private UserAccount linkExistingPhoneAccount(
            UserAccount account,
            GoogleProfile profile,
            ChannelLinkChallenge challenge,
            String sourceIp,
            String userAgent
    ) {
        account = refreshExpiredLock(account, sourceIp, userAgent);
        ensureAccountAvailable(account, sourceIp, userAgent);

        if (!account.isEmailVerified() || !account.getEmail().equalsIgnoreCase(profile.email())) {
            recordConflict(account.getEmail(), sourceIp, userAgent, "Google email does not match verified phone-account email");
            throw new GoogleAuthenticationException("Account linking is required");
        }

        if (externalIdentityRepository.findByUserIdAndProvider(account.getId(), ExternalIdentityProvider.GOOGLE).isPresent()) {
            recordConflict(account.getEmail(), sourceIp, userAgent, "IAM user is already linked to another Google subject");
            throw new GoogleAuthenticationException("Account linking is required");
        }

        ExternalIdentity identity = new ExternalIdentity();
        identity.setProvider(ExternalIdentityProvider.GOOGLE);
        identity.setProviderSubject(profile.subject());
        identity.setProviderEmail(profile.email());
        identity.setUserId(account.getId());
        identity.setLastLoginAt(Instant.now());
        externalIdentityRepository.save(identity);

        channelLinkChallengeService.consumeLoaded(challenge);
        channelAuthenticationService.recordWhatsappAuthentication(account, challenge.getPhoneNumber(), sourceIp, userAgent);
        markGoogleLogin(account, Instant.now());

        auditLogService.record(
                AuditEventType.GOOGLE_IDENTITY_LINKED,
                account.getId(),
                account.getEmail(),
                sourceIp,
                userAgent,
                "Google identity linked to existing IAM user"
        );
        auditLogService.record(
                AuditEventType.GOOGLE_LOGIN_SUCCESS,
                account.getId(),
                account.getEmail(),
                sourceIp,
                userAgent,
                "Google login succeeded"
        );

        return account;
    }

    private UserAccount registerTraveller(
            GoogleProfile profile,
            ChannelLinkChallenge challenge,
            String sourceIp,
            String userAgent
    ) {
        Role travellerRole = roleRepository.findByName(RoleNames.TRAVELLER)
                .orElseThrow(() -> new GoogleAuthenticationException("Default traveller role is unavailable"));

        UserAccount account = new UserAccount();
        account.setFirstName(profile.firstName());
        account.setLastName(profile.lastName());
        account.setEmail(profile.email());
        account.setEmailVerified(true);
        account.setPhoneNumber(challenge.getPhoneNumber());
        account.setPassword(unusablePassword());
        account.setPasswordLoginEnabled(false);
        account.setRoleId(travellerRole.getId());
        markGoogleLogin(account, Instant.now());
        userRepository.save(account);

        ExternalIdentity identity = new ExternalIdentity();
        identity.setProvider(ExternalIdentityProvider.GOOGLE);
        identity.setProviderSubject(profile.subject());
        identity.setProviderEmail(profile.email());
        identity.setUserId(account.getId());
        identity.setLastLoginAt(Instant.now());
        externalIdentityRepository.save(identity);

        channelLinkChallengeService.consumeLoaded(challenge);
        channelAuthenticationService.recordWhatsappAuthentication(account, challenge.getPhoneNumber(), sourceIp, userAgent);

        auditLogService.record(
                AuditEventType.GOOGLE_TRAVELLER_REGISTRATION,
                account.getId(),
                account.getEmail(),
                sourceIp,
                userAgent,
                "Google traveller registration completed"
        );
        auditLogService.record(
                AuditEventType.GOOGLE_LOGIN_SUCCESS,
                account.getId(),
                account.getEmail(),
                sourceIp,
                userAgent,
                "Google login succeeded"
        );

        return account;
    }

    private void validateProfile(GoogleProfile profile, String sourceIp, String userAgent) {
        if (profile.subject() == null) {
            recordFailure(profile.email(), sourceIp, userAgent, "Google profile is missing subject");
            throw new GoogleAuthenticationException("Google authentication could not be completed");
        }

        if (profile.email() == null) {
            recordFailure(null, sourceIp, userAgent, "Google profile is missing email");
            throw new GoogleAuthenticationException("Google authentication could not be completed");
        }

        if (!profile.emailVerified()) {
            recordFailure(profile.email(), sourceIp, userAgent, "Google email is not verified");
            throw new GoogleAuthenticationException("Google authentication could not be completed");
        }

        if (profile.firstName() == null || profile.lastName() == null) {
            recordFailure(profile.email(), sourceIp, userAgent, "Google profile completion is required");
            throw new GoogleAuthenticationException("Profile completion is required");
        }
    }

    private ChannelLinkChallenge requireChallenge(UUID channelLinkChallengeId, String sourceIp, String userAgent) {
        try {
            return channelLinkChallengeService.requireUsableForUpdate(channelLinkChallengeId, sourceIp, userAgent);
        }
        catch (ChannelLinkChallengeException exception) {
            throw new GoogleAuthenticationException("Invalid channel link challenge");
        }
    }

    private UserAccount refreshExpiredLock(UserAccount account, String sourceIp, String userAgent) {
        loginAttemptService.unlockIfExpired(account.getEmail(), sourceIp, userAgent);
        return userRepository.findByIdAndDeletedFalse(account.getId()).orElse(account);
    }

    private void ensureAccountAvailable(UserAccount account, String sourceIp, String userAgent) {
        if (!account.isEnabled() || account.isDeleted() || !account.isAccountNonLocked()) {
            recordFailure(account.getEmail(), sourceIp, userAgent, "IAM account is unavailable");
            throw new GoogleAuthenticationException("Invalid credentials or account unavailable");
        }
    }

    private void markGoogleLogin(UserAccount account, Instant now) {
        account.setFailedLoginAttempts(0);
        account.setLastFailedLoginAt(null);
        account.setLastLoginAt(now);
        account.setLastAuthenticationMethod("GOOGLE");
    }

    private String unusablePassword() {
        byte[] bytes = new byte[UNUSABLE_PASSWORD_BYTES];
        secureRandom.nextBytes(bytes);
        return passwordEncoder.encode("google-only:" + Base64.getUrlEncoder().withoutPadding().encodeToString(bytes));
    }

    private void recordFailure(String email, String sourceIp, String userAgent, String details) {
        auditLogService.record(
                AuditEventType.GOOGLE_LOGIN_FAILURE,
                null,
                email == null ? null : email.toLowerCase(Locale.ROOT),
                sourceIp,
                userAgent,
                details
        );
    }

    private void recordConflict(String email, String sourceIp, String userAgent, String details) {
        auditLogService.record(
                AuditEventType.ACCOUNT_LINKING_CONFLICT,
                null,
                email == null ? null : email.toLowerCase(Locale.ROOT),
                sourceIp,
                userAgent,
                details
        );
    }
}
