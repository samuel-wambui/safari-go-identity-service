package com.NgariTech.identity_service.user;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import jakarta.persistence.LockModeType;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface UserRepository extends JpaRepository<UserAccount, UUID> {

	boolean existsByEmail(String email);

	boolean existsByPhoneNumber(String phoneNumber);

	Optional<UserAccount> findByEmail(String email);

	Optional<UserAccount> findByEmailIgnoreCase(String email);

	Optional<UserAccount> findByEmailIgnoreCaseAndDeletedFalse(String email);

	Optional<UserAccount> findByPhoneNumberAndDeletedFalse(String phoneNumber);

	Optional<UserAccount> findByIdAndDeletedFalse(UUID id);

	long countByRoleId(String roleId);

	@Lock(LockModeType.PESSIMISTIC_WRITE)
	@Query("""
			select user
			from UserAccount user
			where lower(user.email) = lower(:email)
			  and user.deleted = false
			""")
	Optional<UserAccount> findForLoginUpdate(@Param("email") String email);

	@Query("""
			select user
			from UserAccount user
			where user.deleted = false
			  and replace(replace(replace(replace(replace(replace(user.phoneNumber, ' ', ''), '-', ''), '(', ''), ')', ''), '.', ''), '+', '') = :phoneNumber
			""")
	Optional<UserAccount> findByNormalizedPhoneNumberAndDeletedFalse(@Param("phoneNumber") String phoneNumber);

	@Query("""
			select user
			from UserAccount user
			where user.deleted = :deleted
			  and (
			    :query is null
			    or lower(user.firstName) like lower(concat('%', :query, '%'))
			    or lower(user.lastName) like lower(concat('%', :query, '%'))
			    or lower(user.email) like lower(concat('%', :query, '%'))
			    or lower(user.phoneNumber) like lower(concat('%', :query, '%'))
			  )
			order by user.createdAt desc
			""")
	List<UserAccount> searchUsers(@Param("query") String query, @Param("deleted") boolean deleted);
}
