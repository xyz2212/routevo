package com.reutevo.oreo.account;

import java.time.Instant;
import java.util.UUID;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

@Entity
@Table(name = "identity_action_tokens")
public class IdentityActionToken {

	@Id
	private UUID id;

	@Column(name = "username", nullable = false, length = 254)
	private String email;

	@Column(name = "token_hash", nullable = false, unique = true, length = 64)
	private String tokenHash;

	@Enumerated(EnumType.STRING)
	@Column(nullable = false, length = 32)
	private Purpose purpose;

	@Column(name = "expires_at", nullable = false)
	private Instant expiresAt;

	@Column(name = "used_at")
	private Instant usedAt;

	protected IdentityActionToken() {
	}

	public IdentityActionToken(String email, String tokenHash, Purpose purpose, Instant expiresAt) {
		this.id = UUID.randomUUID();
		this.email = email;
		this.tokenHash = tokenHash;
		this.purpose = purpose;
		this.expiresAt = expiresAt;
	}

	public String getEmail() {
		return email;
	}

	public Purpose getPurpose() {
		return purpose;
	}

	public Instant getExpiresAt() {
		return expiresAt;
	}

	public boolean isUsableAt(Instant now) {
		return usedAt == null && expiresAt.isAfter(now);
	}

	public void markUsed(Instant usedAt) {
		this.usedAt = usedAt;
	}

	public enum Purpose {
		EMAIL_VERIFICATION,
		PASSWORD_RESET,
		ADMIN_INVITATION
	}
}
