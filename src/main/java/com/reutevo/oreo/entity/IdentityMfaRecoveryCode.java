package com.reutevo.oreo.entity;

import java.time.Instant;
import java.util.UUID;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

@Entity
@Table(name = "identity_mfa_recovery_codes")
public class IdentityMfaRecoveryCode {

	@Id
	private UUID id;

	@Column(name = "username", nullable = false, length = 254)
	private String email;

	@Column(name = "code_hash", nullable = false, unique = true, length = 64)
	private String codeHash;

	@Column(name = "used_at")
	private Instant usedAt;

	protected IdentityMfaRecoveryCode() {
	}

	public IdentityMfaRecoveryCode(String email, String codeHash) {
		this.id = UUID.randomUUID();
		this.email = email;
		this.codeHash = codeHash;
	}

	public void consume(Instant consumedAt) {
		usedAt = consumedAt;
	}

	public boolean isUnused() {
		return usedAt == null;
	}
}
