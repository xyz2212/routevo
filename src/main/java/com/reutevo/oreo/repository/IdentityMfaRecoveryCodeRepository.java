package com.reutevo.oreo.repository;

import com.reutevo.oreo.entity.IdentityMfaRecoveryCode;
import java.util.Optional;
import java.util.UUID;

import jakarta.persistence.LockModeType;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface IdentityMfaRecoveryCodeRepository
		extends JpaRepository<IdentityMfaRecoveryCode, UUID> {

	@Lock(LockModeType.PESSIMISTIC_WRITE)
	@Query("""
			select code from IdentityMfaRecoveryCode code
			where code.email = :email and code.codeHash = :codeHash and code.usedAt is null
			""")
	Optional<IdentityMfaRecoveryCode> findUnusedForUpdate(
			@Param("email") String email, @Param("codeHash") String codeHash);

	@Modifying
	@Query("delete from IdentityMfaRecoveryCode code where code.email = :email")
	void deleteAllByEmail(@Param("email") String email);
}
