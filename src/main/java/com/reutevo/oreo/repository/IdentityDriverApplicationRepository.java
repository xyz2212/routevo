package com.reutevo.oreo.repository;

import com.reutevo.oreo.entity.IdentityDriverApplication;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import jakarta.persistence.LockModeType;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface IdentityDriverApplicationRepository extends JpaRepository<IdentityDriverApplication, UUID> {
	boolean existsByApplicantEmail(String applicantEmail);

	Optional<IdentityDriverApplication> findByApplicantEmail(String applicantEmail);

	@Lock(LockModeType.PESSIMISTIC_WRITE)
	@Query("select application from IdentityDriverApplication application "
			+ "where application.applicantEmail = :applicantEmail")
	Optional<IdentityDriverApplication> findByApplicantEmailForUpdate(
			@Param("applicantEmail") String applicantEmail);

	List<IdentityDriverApplication> findAllByOrderBySubmittedAtAsc();

	@Lock(LockModeType.PESSIMISTIC_WRITE)
	@Query("select application from IdentityDriverApplication application where application.id = :id")
	Optional<IdentityDriverApplication> findByIdForUpdate(@Param("id") UUID id);
}
