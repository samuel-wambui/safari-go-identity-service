package com.NgariTech.identity_service.common.api;

import java.time.Instant;

public record ApiResponse<T>(
        String message,
        String code,
        T data,
        Instant timestamp
) {

    public static <T> ApiResponse<T> success(String message, T data) {
        return new ApiResponse<>(message, ApiCode.SUCCESS, data, Instant.now());
    }

    public static <T> ApiResponse<T> created(String message, T data) {
        return new ApiResponse<>(message, ApiCode.CREATED, data, Instant.now());
    }

    public static <T> ApiResponse<T> failure(String message, String code, T data) {
        return new ApiResponse<>(message, code, data, Instant.now());
    }
}
