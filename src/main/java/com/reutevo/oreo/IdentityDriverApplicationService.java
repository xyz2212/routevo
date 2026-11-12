package com.reutevo.oreo;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

@Service
public class IdentityDriverApplicationService {

	private final IdentityDriverApplicationRepository applications;
	private final IdentityUserRepository users;

	public IdentityDriverApplicationService(
			IdentityDriverApplicationRepository applications, IdentityUserRepository users) {
		this.applications = applications;
		this.users = users;
	}

	@Transactional
	public DriverApplicationView submit(String applicantEmail, DriverApplicationRequest request) {
		IdentityUser applicant = users.findByEmailForUpdate(applicantEmail).orElseThrow();
		if (!applicant.getRoles().contains(IdentityRole.CUSTOMER)) {
			throw new ResponseStatusException(HttpStatus.FORBIDDEN);
		}
		if (applications.existsByApplicantEmail(applicantEmail)) {
			throw new ResponseStatusException(HttpStatus.CONFLICT, "A driver application already exists.");
		}
		IdentityDriverApplication application = IdentityDriverApplication.submit(
				applicantEmail, request.vehicleType(), request.serviceArea().trim(), Instant.now());
		return view(applications.save(application), applicant);
	}

	@Transactional
	public DriverApplicationView updateAfterInformationRequest(
			String applicantEmail, DriverApplicationRequest request) {
		IdentityDriverApplication application = applications.findByApplicantEmailForUpdate(applicantEmail)
				.orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND));
		if (application.getStatus() != DriverApplicationStatus.NEEDS_INFORMATION) {
			throw new ResponseStatusException(
					HttpStatus.CONFLICT, "This application is not waiting for more information.");
		}
		application.updateAfterInformationRequest(request.vehicleType(), request.serviceArea().trim());
		return view(application, users.findById(applicantEmail).orElseThrow());
	}

	@Transactional(readOnly = true)
	public DriverApplicationView findByApplicant(String applicantEmail) {
		return applications.findByApplicantEmail(applicantEmail)
				.map(application -> view(application, users.findById(applicantEmail).orElseThrow()))
				.orElse(null);
	}

	@Transactional(readOnly = true)
	public List<DriverApplicationView> findAllForReview() {
		return applications.findAllByOrderBySubmittedAtAsc().stream()
				.map(application -> view(application,
						users.findById(application.getApplicantEmail()).orElseThrow()))
				.toList();
	}

	@Transactional
	public DriverApplicationView review(
			UUID applicationId, DriverApplicationReviewOutcome outcome, String administratorEmail) {
		IdentityDriverApplication application = applications.findByIdForUpdate(applicationId)
				.orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND));
		if (application.getStatus() != DriverApplicationStatus.PENDING
				&& application.getStatus() != DriverApplicationStatus.NEEDS_INFORMATION) {
			throw new ResponseStatusException(HttpStatus.CONFLICT, "This driver application is already resolved.");
		}
		application.review(DriverApplicationStatus.valueOf(outcome.name()), administratorEmail, Instant.now());
		return view(application, users.findById(application.getApplicantEmail()).orElseThrow());
	}

	private static DriverApplicationView view(
			IdentityDriverApplication application, IdentityUser applicant) {
		return new DriverApplicationView(
				application.getId(),
				applicant.getEmail(),
				applicant.getDisplayName(),
				applicant.getPhone(),
				application.getVehicleType(),
				application.getServiceArea(),
				application.getStatus(),
				application.getSubmittedAt(),
				application.getReviewedBy(),
				application.getReviewedAt());
	}

	public record DriverApplicationRequest(
			@jakarta.validation.constraints.NotNull DriverVehicleType vehicleType,
			@jakarta.validation.constraints.NotBlank @jakarta.validation.constraints.Size(max = 120)
			String serviceArea) {
	}

	public record DriverApplicationReviewRequest(
			@jakarta.validation.constraints.NotNull DriverApplicationReviewOutcome outcome) {
	}

	public record DriverApplicationView(
			UUID id,
			String applicantEmail,
			String applicantName,
			String applicantPhone,
			DriverVehicleType vehicleType,
			String serviceArea,
			DriverApplicationStatus status,
			Instant submittedAt,
			String reviewedBy,
			Instant reviewedAt) {
	}
}
