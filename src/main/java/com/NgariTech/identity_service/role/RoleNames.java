package com.NgariTech.identity_service.role;

import java.util.List;
import java.util.regex.Pattern;

public final class RoleNames {

    public static final String USER_ID = "r001";
    public static final String ADMIN_ID = "r002";
    public static final String SUPER_ADMIN_ID = "r003";
    public static final String TRAVELLER_ID = "r004";

    public static final String USER = "USER";
    public static final String ADMIN = "ADMIN";
    public static final String SUPER_ADMIN = "SUPER_ADMIN";
    public static final String TRAVELLER = "TRAVELLER";

    public static final List<DefaultRole> DEFAULT_ROLES = List.of(
            new DefaultRole(USER_ID, USER, "Standard user role"),
            new DefaultRole(ADMIN_ID, ADMIN, "Administrator role"),
            new DefaultRole(SUPER_ADMIN_ID, SUPER_ADMIN, "Super administrator role"),
            new DefaultRole(TRAVELLER_ID, TRAVELLER, "Default role assigned during registration")
    );

    private static final Pattern VALID_ROLE_NAME = Pattern.compile("^[A-Z][A-Z0-9_]{1,49}$");
    private static final Pattern VALID_ROLE_ID = Pattern.compile("^r\\d{3,}$");

    private RoleNames() {
    }

    public static String normalize(String name) {
        if (name == null || name.isBlank()) {
            throw new IllegalArgumentException("Role name is required");
        }

        String normalized = name.trim()
                .replaceAll("[\\s-]+", "_")
                .toUpperCase();

        if (!VALID_ROLE_NAME.matcher(normalized).matches()) {
            throw new IllegalArgumentException("Role name must contain only letters, numbers, and underscores");
        }

        return normalized;
    }

    public static String normalizeId(String id) {
        if (id == null || id.isBlank()) {
            throw new IllegalArgumentException("Role id is required");
        }

        String normalized = id.trim().toLowerCase();
        if (!VALID_ROLE_ID.matcher(normalized).matches()) {
            throw new IllegalArgumentException("Role id must use format r001");
        }

        return normalized;
    }

    public record DefaultRole(String id, String name, String description) {
    }
}
