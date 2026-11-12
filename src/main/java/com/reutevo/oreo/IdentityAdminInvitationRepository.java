package com.reutevo.oreo;

import java.util.Optional;

import jakarta.persistence.LockModeType;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface IdentityAdminInvitationRepository extends JpaRepository<IdentityAdminInvitation, String> {

	@Lock(LockModeType.PESSIMISTIC_WRITE)
	@Query("select invitation from IdentityAdminInvitation invitation where invitation.email = :email")
	Optional<IdentityAdminInvitation> findByEmailForUpdate(@Param("email") String email);

	@Lock(LockModeType.PESSIMISTIC_WRITE)
	@Query("select invitation from IdentityAdminInvitation invitation where invitation.tokenHash = :tokenHash")
	Optional<IdentityAdminInvitation> findByTokenHashForUpdate(@Param("tokenHash") String tokenHash);
}
