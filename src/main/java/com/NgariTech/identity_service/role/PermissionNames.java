package com.NgariTech.identity_service.role;

import java.util.List;
import java.util.regex.Pattern;

public final class PermissionNames {

    public static final String MENU_READ_ID = "p001";
    public static final String MENU_CREATE_ID = "p002";
    public static final String MENU_UPDATE_ID = "p003";
    public static final String MENU_DELETE_ID = "p004";
    public static final String USER_READ_ID = "p005";
    public static final String ROLE_ASSIGN_ID = "p006";
    public static final String TRAVEL_READ_ID = "p007";
    public static final String TRAVEL_CREATE_ID = "p008";
    public static final String CHANNEL_AUTH_CREATE_ID = "p009";
    public static final String PAYMENT_CREATE_ID = "p010";
    public static final String PAYMENT_READ_ID = "p011";

    public static final String MENU_READ = "menu:read";
    public static final String MENU_CREATE = "menu:create";
    public static final String MENU_UPDATE = "menu:update";
    public static final String MENU_DELETE = "menu:delete";
    public static final String USER_READ = "user:read";
    public static final String ROLE_ASSIGN = "role:assign";
    public static final String TRAVEL_READ = "travel:read";
    public static final String TRAVEL_CREATE = "travel:create";
    public static final String CHANNEL_AUTH_CREATE = "channel_auth:create";
    public static final String PAYMENT_CREATE = "payment:create";
    public static final String PAYMENT_READ = "payment:read";

    public static final List<DefaultPermission> DEFAULT_PERMISSIONS = List.of(
            new DefaultPermission(MENU_READ_ID, MENU_READ, "View menus"),
            new DefaultPermission(MENU_CREATE_ID, MENU_CREATE, "Create menus"),
            new DefaultPermission(MENU_UPDATE_ID, MENU_UPDATE, "Update menus"),
            new DefaultPermission(MENU_DELETE_ID, MENU_DELETE, "Delete menus"),
            new DefaultPermission(USER_READ_ID, USER_READ, "View users"),
            new DefaultPermission(ROLE_ASSIGN_ID, ROLE_ASSIGN, "Assign roles"),
            new DefaultPermission(TRAVEL_READ_ID, TRAVEL_READ, "View travel services"),
            new DefaultPermission(TRAVEL_CREATE_ID, TRAVEL_CREATE, "Create travel service requests"),
            new DefaultPermission(CHANNEL_AUTH_CREATE_ID, CHANNEL_AUTH_CREATE, "Create channel authentication link challenges"),
            new DefaultPermission(PAYMENT_CREATE_ID, PAYMENT_CREATE, "Initialize a payment for an owned booking"),
            new DefaultPermission(PAYMENT_READ_ID, PAYMENT_READ, "Read an owned payment")
    );

    private static final Pattern VALID_PERMISSION_NAME = Pattern.compile("^[a-z][a-z0-9_-]*:[a-z][a-z0-9_-]*$");
    private static final Pattern VALID_PERMISSION_ID = Pattern.compile("^p\\d{3,}$");

    private PermissionNames() {
    }

    public static String normalize(String name) {
        if (name == null || name.isBlank()) {
            throw new IllegalArgumentException("Permission name is required");
        }

        String normalized = name.trim().toLowerCase();
        if (!VALID_PERMISSION_NAME.matcher(normalized).matches()) {
            throw new IllegalArgumentException("Permission name must use resource:action format");
        }

        return normalized;
    }

    public static String normalizeId(String id) {
        if (id == null || id.isBlank()) {
            throw new IllegalArgumentException("Permission id is required");
        }

        String normalized = id.trim().toLowerCase();
        if (!VALID_PERMISSION_ID.matcher(normalized).matches()) {
            throw new IllegalArgumentException("Permission id must use format p001");
        }

        return normalized;
    }

    public record DefaultPermission(String id, String name, String description) {
    }
}
