package com.NgariTech.identity_service.auth.channel;

import com.NgariTech.identity_service.auth.channel.dto.ChannelLocalLoginRequest;
import com.NgariTech.identity_service.auth.channel.dto.ChannelLocalRegisterRequest;
import com.NgariTech.identity_service.common.exception.DuplicateResourceException;
import com.NgariTech.identity_service.role.Role;
import com.NgariTech.identity_service.role.RoleNames;
import com.NgariTech.identity_service.role.RoleRepository;
import com.NgariTech.identity_service.security.IamUserPrincipalService;
import com.NgariTech.identity_service.user.UserAccount;
import com.NgariTech.identity_service.user.UserRepository;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.Locale;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class ChannelLocalAuthenticationService {

    private final ChannelLinkChallengeService channelLinkChallengeService;
    private final ChannelAuthenticationService channelAuthenticationService;
    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;
    private final IamUserPrincipalService iamUserPrincipalService;
    private final SecurityContextRepository securityContextRepository = new HttpSessionSecurityContextRepository();

    @Transactional
    public UserAccount login(
            UUID challengeId,
            ChannelLocalLoginRequest request,
            HttpServletRequest servletRequest,
            HttpServletResponse servletResponse
    ) {
        ChannelLinkChallenge challenge = channelLinkChallengeService.requireUsableForUpdate(
                challengeId,
                sourceIp(servletRequest),
                servletRequest.getHeader("User-Agent")
        );

        String email = normalizeEmail(request.email());
        UserAccount candidate = userRepository.findByEmailIgnoreCaseAndDeletedFalse(email)
                .orElseThrow(() -> new BadCredentialsException("Invalid credentials or account unavailable"));
        if (!challenge.getPhoneNumber().equals(candidate.getPhoneNumber())) {
            throw new BadCredentialsException("Invalid credentials or account unavailable");
        }

        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(email, request.password())
        );

        UserAccount account = userRepository.findByIdAndDeletedFalse(UUID.fromString(authentication.getName()))
                .orElseThrow(() -> new BadCredentialsException("Invalid credentials or account unavailable"));

        channelLinkChallengeService.consumeLoaded(challenge);
        channelAuthenticationService.recordWhatsappAuthentication(
                account,
                challenge.getPhoneNumber(),
                sourceIp(servletRequest),
                servletRequest.getHeader("User-Agent")
        );
        saveSecurityContext(account, authentication.getDetails(), servletRequest, servletResponse);
        return account;
    }

    @Transactional
    public UserAccount register(
            UUID challengeId,
            ChannelLocalRegisterRequest request,
            HttpServletRequest servletRequest,
            HttpServletResponse servletResponse
    ) {
        if (request.password() == null || !request.password().equals(request.confirmPassword())) {
            throw new DuplicateResourceException("Account could not be created");
        }

        ChannelLinkChallenge challenge = channelLinkChallengeService.requireUsableForUpdate(
                challengeId,
                sourceIp(servletRequest),
                servletRequest.getHeader("User-Agent")
        );

        String email = normalizeEmail(request.email());
        if (userRepository.existsByEmail(email)) {
            throw new DuplicateResourceException("Account could not be created");
        }

        if (userRepository.existsByPhoneNumber(challenge.getPhoneNumber())) {
            throw new DuplicateResourceException("Account could not be created");
        }

        Role travellerRole = roleRepository.findByName(RoleNames.TRAVELLER)
                .orElseThrow(() -> new IllegalStateException("Default role TRAVELLER not found"));

        UserAccount account = new UserAccount();
        account.setFirstName(request.firstName().trim());
        account.setLastName(request.lastName().trim());
        account.setEmail(email);
        account.setPassword(passwordEncoder.encode(request.password()));
        account.setPasswordLoginEnabled(true);
        account.setPhoneNumber(challenge.getPhoneNumber());
        account.setRoleId(travellerRole.getId());
        account.setLastLoginAt(Instant.now());
        account.setLastAuthenticationMethod("PASSWORD");

        try {
            userRepository.save(account);
        }
        catch (DataIntegrityViolationException exception) {
            throw new DuplicateResourceException("Account could not be created");
        }

        channelLinkChallengeService.consumeLoaded(challenge);
        channelAuthenticationService.recordWhatsappAuthentication(
                account,
                challenge.getPhoneNumber(),
                sourceIp(servletRequest),
                servletRequest.getHeader("User-Agent")
        );
        saveSecurityContext(account, null, servletRequest, servletResponse);
        return account;
    }

    private void saveSecurityContext(
            UserAccount account,
            Object details,
            HttpServletRequest servletRequest,
            HttpServletResponse servletResponse
    ) {
        UserDetails userDetails = iamUserPrincipalService.userDetails(account);
        UsernamePasswordAuthenticationToken localAuthentication = UsernamePasswordAuthenticationToken.authenticated(
                userDetails,
                "CHANNEL",
                userDetails.getAuthorities()
        );
        localAuthentication.setDetails(details);

        SecurityContext context = SecurityContextHolder.createEmptyContext();
        context.setAuthentication(localAuthentication);
        SecurityContextHolder.setContext(context);
        securityContextRepository.saveContext(context, servletRequest, servletResponse);
    }

    private String normalizeEmail(String email) {
        return email.trim().toLowerCase(Locale.ROOT);
    }

    private String sourceIp(HttpServletRequest request) {
        String forwardedFor = request.getHeader("X-Forwarded-For");
        if (forwardedFor != null && !forwardedFor.isBlank()) {
            return forwardedFor.split(",")[0].trim();
        }

        return request.getRemoteAddr();
    }
}
