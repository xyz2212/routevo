package com.reutevo.oreo;

import java.time.Instant;
import java.util.UUID;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import jakarta.persistence.UniqueConstraint;

@Entity
@Table(name = "identity_driver_applications",
		uniqueConstraints = @UniqueConstraint(name = "uk_driver_application_applicant", columnNames = "username"))
public class IdentityDriverApplication {

	@Id
	@GeneratedValue
	private UUID id;

	@Column(name = "username", nullable = false, length = 254)
	private String applicantEmail;

	@Enumerated(EnumType.STRING)
	@Column(name = "vehicle_type", nullable = false, length = 32)
	private DriverVehicleType vehicleType;

	@Column(name = "service_area", nullable = false, length = 120)
	private String serviceArea;

	@Enumerated(EnumType.STRING)
	@Column(nullable = false, length = 40)
	private DriverApplicationStatus status;

	@Column(name = "submitted_at", nullable = false)
	private Instant submittedAt;

	@Column(name = "reviewed_by", length = 254)
	private String reviewedBy;

	@Column(name = "reviewed_at")
	private Instant reviewedAt;

	protected IdentityDriverApplication() {
	}

	private IdentityDriverApplication(
			String applicantEmail, DriverVehicleType vehicleType, String serviceArea, Instant submittedAt) {
		this.applicantEmail = applicantEmail;
		this.vehicleType = vehicleType;
		this.serviceArea = serviceArea;
		this.status = DriverApplicationStatus.PENDING;
		this.submittedAt = submittedAt;
	}

	public static IdentityDriverApplication submit(
			String applicantEmail, DriverVehicleType vehicleType, String serviceArea, Instant submittedAt) {
		return new IdentityDriverApplication(applicantEmail, vehicleType, serviceArea, submittedAt);
	}

	public UUID getId() {
		return id;
	}

	public String getApplicantEmail() {
		return applicantEmail;
	}

	public DriverVehicleType getVehicleType() {
		return vehicleType;
	}

	public String getServiceArea() {
		return serviceArea;
	}

	public DriverApplicationStatus getStatus() {
		return status;
	}

	public Instant getSubmittedAt() {
		return submittedAt;
	}

	public String getReviewedBy() {
		return reviewedBy;
	}

	public Instant getReviewedAt() {
		return reviewedAt;
	}

	public void updateAfterInformationRequest(
			DriverVehicleType updatedVehicleType, String updatedServiceArea) {
		if (status != DriverApplicationStatus.NEEDS_INFORMATION) {
			throw new IllegalStateException("Only applications needing information can be updated");
		}
		vehicleType = updatedVehicleType;
		serviceArea = updatedServiceArea;
		status = DriverApplicationStatus.PENDING;
		reviewedBy = null;
		reviewedAt = null;
	}

	public void review(DriverApplicationStatus outcome, String administratorEmail, Instant reviewedAt) {
		if (status != DriverApplicationStatus.PENDING
				&& status != DriverApplicationStatus.NEEDS_INFORMATION) {
			throw new IllegalStateException("This driver application has already been resolved");
		}
		if (outcome == DriverApplicationStatus.PENDING) {
			throw new IllegalArgumentException("A review outcome is required");
		}
		status = outcome;
		reviewedBy = administratorEmail;
		this.reviewedAt = reviewedAt;
	}
}
