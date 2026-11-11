package com.NgariTech.identity_service.user;

import com.NgariTech.identity_service.auth.AuditEventType;
import com.NgariTech.identity_service.auth.AuditLogService;
import com.NgariTech.identity_service.auth.oidc.AuthorizationRevocationService;
import com.NgariTech.identity_service.common.exception.DuplicateResourceException;
import com.NgariTech.identity_service.common.exception.ResourceNotFoundException;
import com.NgariTech.identity_service.role.Role;
import com.NgariTech.identity_service.role.RoleNames;
import com.NgariTech.identity_service.role.RoleRepository;
import com.NgariTech.identity_service.user.dto.RegisterUserRequest;
import com.NgariTech.identity_service.user.dto.UserResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.List;
import java.util.Locale;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class UserService {

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuthorizationRevocationService authorizationRevocationService;
    private final AuditLogService auditLogService;

    @Transactional
    public UserResponse register(RegisterUserRequest request) {
        String email = normalizeEmail(request.email());
        String phoneNumber = PhoneNumberNormalizer.normalize(request.phoneNumber());

        if (userRepository.existsByEmail(email)) {
            throw new DuplicateResourceException("Email is already registered");
        }

        if (userRepository.existsByPhoneNumber(phoneNumber)) {
            throw new DuplicateResourceException("Phone number is already registered");
        }

        UserAccount user = new UserAccount();
        user.setFirstName(request.firstName().trim());
        user.setLastName(request.lastName().trim());
        user.setEmail(email);
        user.setPassword(passwordEncoder.encode(request.password()));
        user.setPasswordLoginEnabled(true);
        user.setPhoneNumber(phoneNumber);
        user.setRoleId(defaultRegistrationRole().getId());

        try {
            return UserResponse.from(userRepository.save(user));
        }
        catch (DataIntegrityViolationException exception) {
            throw new DuplicateResourceException("Email or phone number is already registered");
        }
    }

    @Transactional(readOnly = true)
    public UserResponse getById(UUID id) {
        return userRepository.findByIdAndDeletedFalse(id)
                .map(UserResponse::from)
                .orElseThrow(() -> new ResourceNotFoundException("User not found"));
    }

    @Transactional(readOnly = true)
    public List<UserResponse> search(String query, Boolean deleted) {
        String searchQuery = query == null || query.isBlank() ? null : query.trim();
        boolean deletedFilter = Boolean.TRUE.equals(deleted);

        return userRepository.searchUsers(searchQuery, deletedFilter)
                .stream()
                .map(UserResponse::from)
                .toList();
    }

    @Transactional
    public void delete(UUID id) {
        UserAccount user = userRepository.findByIdAndDeletedFalse(id)
                .orElseThrow(() -> new ResourceNotFoundException("User not found"));

        user.setDeleted(true);
        user.setDeletedAt(Instant.now());
        user.setEnabled(false);
        userRepository.save(user);
        authorizationRevocationService.revokeAllForUser(user);
        auditLogService.record(
                AuditEventType.ACCOUNT_DISABLED,
                user.getId(),
                user.getEmail(),
                null,
                null,
                "User account was deleted and disabled"
        );
    }

    private String normalizeEmail(String email) {
        return email.trim().toLowerCase(Locale.ROOT);
    }

    private Role defaultRegistrationRole() {
        return roleRepository.findByName(RoleNames.TRAVELLER)
                .orElseThrow(() -> new ResourceNotFoundException("Default role TRAVELLER not found"));
    }
}
