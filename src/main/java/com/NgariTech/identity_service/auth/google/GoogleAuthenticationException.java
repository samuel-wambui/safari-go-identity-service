package com.NgariTech.identity_service.auth.google;

import org.springframework.security.core.AuthenticationException;

public class GoogleAuthenticationException extends AuthenticationException {

    public GoogleAuthenticationException(String message) {
        super(message);
    }
}
