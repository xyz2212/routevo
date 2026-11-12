package com.reutevo.oreo;

import java.util.Optional;
import java.time.Instant;
import java.util.UUID;

import jakarta.persistence.LockModeType;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface IdentityActionTokenRepository extends JpaRepository<IdentityActionToken, java.util.UUID> {
	Optional<IdentityActionToken> findByTokenHash(String tokenHash);

	@Lock(LockModeType.PESSIMISTIC_WRITE)
	@Query("select token from IdentityActionToken token where token.tokenHash = :tokenHash")
	Optional<IdentityActionToken> findByTokenHashForUpdate(@Param("tokenHash") String tokenHash);

	@Modifying
	@Query("""
			update IdentityActionToken token set token.usedAt = :usedAt
			where token.email = :email and token.purpose = :purpose and token.usedAt is null
			""")
	void invalidateUnused(
			@Param("email") String email,
			@Param("purpose") IdentityActionToken.Purpose purpose,
			@Param("usedAt") Instant usedAt);
}
