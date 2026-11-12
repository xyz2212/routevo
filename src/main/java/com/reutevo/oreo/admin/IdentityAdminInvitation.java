package com.reutevo.oreo.admin;

import java.time.Instant;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

@Entity
@Table(name = "identity_admin_invitations")
public class IdentityAdminInvitation {

	@Id
	@Column(name = "email", length = 254)
	private String email;

	@Column(name = "token_hash", nullable = false, unique = true, length = 64)
	private String tokenHash;

	@Column(name = "expires_at", nullable = false)
	private Instant expiresAt;

	@Column(name = "accepted_at")
	private Instant acceptedAt;

	protected IdentityAdminInvitation() {
	}

	public IdentityAdminInvitation(String email, String tokenHash, Instant expiresAt) {
		this.email = email;
		this.tokenHash = tokenHash;
		this.expiresAt = expiresAt;
	}

	public String getEmail() {
		return email;
	}

	public boolean isUsableAt(Instant now) {
		return acceptedAt == null && expiresAt.isAfter(now);
	}

	public void issue(String tokenHash, Instant expiresAt) {
		this.tokenHash = tokenHash;
		this.expiresAt = expiresAt;
		acceptedAt = null;
	}

	public void accept(Instant acceptedAt) {
		this.acceptedAt = acceptedAt;
	}
}
