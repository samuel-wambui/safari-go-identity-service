package com.NgariTech.identity_service.whatsapp;

import com.NgariTech.identity_service.common.api.ApiResponse;
import com.NgariTech.identity_service.whatsapp.dto.WhatsappAuthStatusResponse;
import com.NgariTech.identity_service.whatsapp.dto.WhatsappDelegatedTokenRequest;
import com.NgariTech.identity_service.whatsapp.dto.WhatsappDelegatedTokenResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/whatsapp")
@RequiredArgsConstructor
public class WhatsappIdentityController {

    private final WhatsappIdentityService whatsappIdentityService;
    private final WhatsappDelegatedTokenService whatsappDelegatedTokenService;

    @GetMapping("/auth/status")
    public ResponseEntity<ApiResponse<WhatsappAuthStatusResponse>> authenticationStatus(
            @RequestParam String phoneNumber
    ) {
        return ResponseEntity.ok(ApiResponse.success(
                "WhatsApp authentication status retrieved",
                whatsappIdentityService.authenticationStatus(phoneNumber)
        ));
    }

    @PostMapping("/auth/tokens")
    public ResponseEntity<ApiResponse<WhatsappDelegatedTokenResponse>> delegatedToken(
            @Valid @RequestBody WhatsappDelegatedTokenRequest request,
            Authentication authentication,
            HttpServletRequest servletRequest
    ) {
        return ResponseEntity.ok(ApiResponse.success(
                "WhatsApp delegated access token issued",
                whatsappDelegatedTokenService.issueDelegatedToken(request, authentication, servletRequest)
        ));
    }
}
