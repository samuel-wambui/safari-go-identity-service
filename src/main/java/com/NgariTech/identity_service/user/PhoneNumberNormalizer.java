package com.NgariTech.identity_service.user;

import java.util.regex.Pattern;

public final class PhoneNumberNormalizer {

    private static final Pattern COMMON_SEPARATORS = Pattern.compile("[\\s().-]+");
    private static final Pattern KENYAN_LOCAL_MOBILE = Pattern.compile("0[17]\\d{8}");

    private PhoneNumberNormalizer() {
    }

    public static String normalize(String phoneNumber) {
        if (phoneNumber == null || phoneNumber.isBlank()) {
            throw new IllegalArgumentException("Phone number is required");
        }

        String normalized = COMMON_SEPARATORS.matcher(phoneNumber.trim()).replaceAll("");
        if (normalized.startsWith("+")) {
            normalized = normalized.substring(1);
        }
        if (normalized.startsWith("00") && normalized.length() > 2) {
            normalized = normalized.substring(2);
        }
        if (KENYAN_LOCAL_MOBILE.matcher(normalized).matches()) {
            normalized = "254" + normalized.substring(1);
        }
        if (normalized.isBlank()) {
            throw new IllegalArgumentException("Phone number is required");
        }

        if (normalized.length() > 30) {
            throw new IllegalArgumentException("Phone number must be 30 characters or fewer");
        }

        return normalized;
    }
}
