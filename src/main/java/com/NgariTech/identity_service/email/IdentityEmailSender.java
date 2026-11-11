package com.NgariTech.identity_service.email;

public interface IdentityEmailSender {

    void sendEmailWithVerificationCode(String toEmail, String subject, String text);
}
