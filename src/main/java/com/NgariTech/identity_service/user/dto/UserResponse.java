package com.NgariTech.identity_service.user.dto;

import com.NgariTech.identity_service.user.UserAccount;

import java.time.Instant;
import java.util.UUID;

public record UserResponse(
		UUID id,
		String firstName,
		String lastName,
		String email,
		String phoneNumber,
		boolean enabled,
		boolean emailVerified,
		boolean accountNonLocked,
		int failedLoginAttempts,
		String roleId,
		boolean deleted,
		Instant deletedAt,
		Instant createdAt,
		Instant updatedAt
) {

	public static UserResponse from(UserAccount user) {
		return new UserResponse(
				user.getId(),
				user.getFirstName(),
				user.getLastName(),
				user.getEmail(),
				user.getPhoneNumber(),
				user.isEnabled(),
				user.isEmailVerified(),
				user.isAccountNonLocked(),
				user.getFailedLoginAttempts(),
				user.getRoleId(),
				user.isDeleted(),
				user.getDeletedAt(),
				user.getCreatedAt(),
				user.getUpdatedAt()
		);
	}
}
