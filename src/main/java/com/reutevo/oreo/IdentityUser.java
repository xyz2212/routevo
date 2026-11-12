package com.reutevo.oreo;

import java.time.Instant;
import java.util.EnumSet;
import java.util.Set;

import jakarta.persistence.CollectionTable;
import jakarta.persistence.Column;
import jakarta.persistence.ElementCollection;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.Table;

@Entity
@Table(name = "identity_users")
public class IdentityUser {

	@Id
	@Column(name = "username", length = 254)
	private String email;

	@Column(name = "password", nullable = false, length = 100)
	private String passwordHash;

	@Column(name = "display_name", nullable = false, length = 120)
	private String displayName;

	@Column(length = 32)
	private String phone;

	@Column(nullable = false)
	private boolean enabled = true;

	@Column(name = "email_verified_at")
	private Instant emailVerifiedAt;

	@Column(name = "mfa_secret_ciphertext", length = 256)
	private String mfaSecretCiphertext;

	@Column(name = "mfa_enabled_at")
	private Instant mfaEnabledAt;

	@Column(name = "mfa_setup_expires_at")
	private Instant mfaSetupExpiresAt;

	@ElementCollection
	@CollectionTable(name = "identity_user_roles", joinColumns = @JoinColumn(name = "username"))
	@Column(name = "role", nullable = false, length = 32)
	@Enumerated(EnumType.STRING)
	private Set<IdentityRole> roles = EnumSet.noneOf(IdentityRole.class);

	protected IdentityUser() {
	}

	public String getUsername() {
		return email;
	}

	public String getPassword() {
		return passwordHash;
	}

	public String getEmail() {
		return email;
	}

	public String getDisplayName() {
		return displayName;
	}

	public String getPhone() {
		return phone;
	}

	public boolean isEnabled() {
		return enabled;
	}

	public Instant getEmailVerifiedAt() {
		return emailVerifiedAt;
	}

	public Set<IdentityRole> getRoles() {
		return Set.copyOf(roles);
	}

	public boolean isEmailVerified() {
		return emailVerifiedAt != null;
	}

	public boolean isMfaEnabled() {
		return mfaEnabledAt != null;
	}

	public String getMfaSecretCiphertext() {
		return mfaSecretCiphertext;
	}

	public Instant getMfaSetupExpiresAt() {
		return mfaSetupExpiresAt;
	}

	public void startMfaEnrollment(String encryptedSecret, Instant expiresAt) {
		if (isMfaEnabled()) {
			throw new IllegalStateException("MFA is already enabled");
		}
		mfaSecretCiphertext = encryptedSecret;
		mfaSetupExpiresAt = expiresAt;
	}

	public void enableMfa(Instant enabledAt) {
		mfaEnabledAt = enabledAt;
		mfaSetupExpiresAt = null;
	}

	public void verifyEmail(Instant verifiedAt) {
		emailVerifiedAt = verifiedAt;
	}

	public void changePassword(String encodedPassword) {
		passwordHash = encodedPassword;
	}

	public void disable() {
		enabled = false;
	}

	public void addRole(IdentityRole role) {
		roles.add(role);
	}

	public static IdentityUser registeredCustomer(
			String email,
			String displayName,
			String phone,
			String encodedPassword) {
		return new IdentityUser(email.trim().toLowerCase(java.util.Locale.ROOT),
				displayName.trim(), phone, encodedPassword,
				EnumSet.of(IdentityRole.CUSTOMER), null);
	}

	public static IdentityUser initialAdmin(String email, String displayName, String encodedPassword) {
		return new IdentityUser(email.trim().toLowerCase(java.util.Locale.ROOT), displayName.trim(), null, encodedPassword,
				EnumSet.of(IdentityRole.ADMIN), Instant.now());
	}

	public static IdentityUser invitedAdministrator(String email, String displayName, String encodedPassword) {
		return new IdentityUser(email, displayName, null, encodedPassword,
				EnumSet.of(IdentityRole.ADMIN), Instant.now());
	}

	private IdentityUser(
			String email,
			String displayName,
			String phone,
			String passwordHash,
			Set<IdentityRole> roles,
			Instant emailVerifiedAt) {
		this.email = email;
		this.displayName = displayName;
		this.phone = phone;
		this.passwordHash = passwordHash;
		this.roles = roles;
		this.emailVerifiedAt = emailVerifiedAt;
	}
}
