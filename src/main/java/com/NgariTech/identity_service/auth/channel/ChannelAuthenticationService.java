package com.NgariTech.identity_service.auth.channel;

import com.NgariTech.identity_service.auth.AuditEventType;
import com.NgariTech.identity_service.auth.AuditLogService;
import com.NgariTech.identity_service.user.PhoneNumberNormalizer;
import com.NgariTech.identity_service.user.UserAccount;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Duration;
import java.time.Instant;
import java.util.List;

@Service
@RequiredArgsConstructor
public class ChannelAuthenticationService {

    private final ChannelAuthenticationRepository channelAuthenticationRepository;
    private final AuditLogService auditLogService;

    @Value("${iam.google.channel-auth-days:7}")
    private long channelAuthDays;

    @Transactional
    public void recordWhatsappAuthentication(UserAccount account, String phoneNumber, String sourceIp, String userAgent) {
        String normalizedPhoneNumber = PhoneNumberNormalizer.normalize(phoneNumber);
        Instant now = Instant.now();
        ChannelAuthentication authentication = channelAuthenticationRepository
                .findByChannelAndPhoneNumber(ChannelLinkChannel.WHATSAPP, normalizedPhoneNumber)
                .orElseGet(ChannelAuthentication::new);

        authentication.setChannel(ChannelLinkChannel.WHATSAPP);
        authentication.setPhoneNumber(normalizedPhoneNumber);
        authentication.setUserId(account.getId());
        authentication.setAuthenticatedAt(now);
        authentication.setExpiresAt(now.plus(Duration.ofDays(channelAuthDays)));
        channelAuthenticationRepository.save(authentication);

        auditLogService.record(
                AuditEventType.CHANNEL_AUTHENTICATION_SUCCESS,
                account.getId(),
                account.getEmail(),
                sourceIp,
                userAgent,
                "WhatsApp channel authentication completed"
        );
    }

    @Transactional(readOnly = true)
    public boolean hasActiveWhatsappAuthentication(UserAccount account, String phoneNumber) {
        String normalizedPhoneNumber = PhoneNumberNormalizer.normalize(phoneNumber);
        return channelAuthenticationRepository
                .findByChannelAndPhoneNumber(ChannelLinkChannel.WHATSAPP, normalizedPhoneNumber)
                .filter(authentication -> account.getId().equals(authentication.getUserId()))
                .filter(authentication -> authentication.getExpiresAt() != null)
                .filter(authentication -> Instant.now().isBefore(authentication.getExpiresAt()))
                .isPresent();
    }

    @Transactional
    public int revokeWhatsappAuthentications(UserAccount account, String sourceIp, String userAgent) {
        Instant now = Instant.now();
        List<ChannelAuthentication> authentications = channelAuthenticationRepository
                .findByChannelAndUserId(ChannelLinkChannel.WHATSAPP, account.getId());

        int revoked = 0;
        for (ChannelAuthentication authentication : authentications) {
            if (authentication.getExpiresAt() != null && now.isBefore(authentication.getExpiresAt())) {
                authentication.setExpiresAt(now);
                revoked++;
            }
        }

        if (revoked > 0) {
            auditLogService.record(
                    AuditEventType.CHANNEL_AUTHENTICATION_REVOKED,
                    account.getId(),
                    account.getEmail(),
                    sourceIp,
                    userAgent,
                    "WhatsApp channel authentication revoked during logout"
            );
        }

        return revoked;
    }
}
