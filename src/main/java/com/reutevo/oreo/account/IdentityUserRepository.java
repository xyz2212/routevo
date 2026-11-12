package com.reutevo.oreo.account;

import java.util.Optional;

import jakarta.persistence.LockModeType;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface IdentityUserRepository extends JpaRepository<IdentityUser, String> {
	boolean existsByEmail(String email);

	@Lock(LockModeType.PESSIMISTIC_WRITE)
	@Query("select user from IdentityUser user where user.email = :email")
	Optional<IdentityUser> findByEmailForUpdate(@Param("email") String email);
}
