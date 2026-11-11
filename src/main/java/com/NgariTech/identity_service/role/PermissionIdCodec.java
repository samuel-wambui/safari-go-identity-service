package com.NgariTech.identity_service.role;

import java.util.Collection;
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.Set;
import java.util.stream.Collectors;

public final class PermissionIdCodec {

    private PermissionIdCodec() {
    }

    public static Set<String> parse(String permissionIds) {
        if (permissionIds == null || permissionIds.isBlank()) {
            return Set.of();
        }

        return Arrays.stream(permissionIds.split("[,\\n]"))
                .map(String::trim)
                .filter(value -> !value.isBlank())
                .map(PermissionNames::normalizeId)
                .collect(Collectors.toCollection(LinkedHashSet::new));
    }

    public static String format(Collection<String> permissionIds) {
        if (permissionIds == null || permissionIds.isEmpty()) {
            return null;
        }

        String formatted = permissionIds.stream()
                .map(PermissionNames::normalizeId)
                .distinct()
                .sorted()
                .collect(Collectors.joining(","));

        return formatted.isBlank() ? null : formatted;
    }
}
