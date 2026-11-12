package com.reutevo.oreo;

import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Locale;
import java.util.Optional;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class IdentityAccountService {

	private static final Duration ACTION_TOKEN_LIFETIME = Duration.ofHours(1);
	private static final SecureRandom SECURE_RANDOM = new SecureRandom();

	private final IdentityUserRepository users;
	private final IdentityActionTokenRepository actionTokens;
	private final PasswordEncoder passwordEncoder;
	private final ApplicationEventPublisher eventPublisher;
	private final IdentitySessionRevoker sessionRevoker;

	public IdentityAccountService(
			IdentityUserRepository users,
			IdentityActionTokenRepository actionTokens,
			PasswordEncoder passwordEncoder,
			ApplicationEventPublisher eventPublisher,
			IdentitySessionRevoker sessionRevoker) {
		this.users = users;
		this.actionTokens = actionTokens;
		this.passwordEncoder = passwordEncoder;
		this.eventPublisher = eventPublisher;
		this.sessionRevoker = sessionRevoker;
	}

	@Transactional
	public void register(String email, String displayName, String phone, String rawPassword) {
		String normalizedEmail = normalizeEmail(email);
		if (users.existsById(normalizedEmail)) {
			return;
		}

		IdentityUser user = IdentityUser.registeredCustomer(
				normalizedEmail,
				displayName.trim(),
				phone == null || phone.isBlank() ? null : phone.trim(),
				passwordEncoder.encode(PasswordPolicy.requireBcryptCompatible(rawPassword)));
		users.save(user);
		issueToken(user, IdentityActionToken.Purpose.EMAIL_VERIFICATION);
	}

	@Transactional
	public void resendVerification(String email) {
		users.findById(normalizeEmail(email))
				.filter(user -> !user.isEmailVerified())
				.ifPresent(user -> issueToken(user, IdentityActionToken.Purpose.EMAIL_VERIFICATION));
	}

	@Transactional
	public boolean verifyEmail(String rawToken) {
		Optional<IdentityActionToken> token = findUsableTokenForUpdate(
				rawToken, IdentityActionToken.Purpose.EMAIL_VERIFICATION);
		if (token.isEmpty()) {
			return false;
		}
		IdentityActionToken actionToken = token.get();
		IdentityUser user = users.findById(actionToken.getEmail()).orElseThrow();
		user.verifyEmail(Instant.now());
		actionToken.markUsed(Instant.now());
		return true;
	}

	@Transactional
	public void requestPasswordReset(String email) {
		users.findById(normalizeEmail(email))
				.ifPresent(user -> issueToken(user, IdentityActionToken.Purpose.PASSWORD_RESET));
	}

	@Transactional
	public boolean resetPassword(String rawToken, String rawPassword) {
		Optional<IdentityActionToken> token = findUsableTokenForUpdate(
				rawToken, IdentityActionToken.Purpose.PASSWORD_RESET);
		if (token.isEmpty()) {
			return false;
		}
		IdentityActionToken actionToken = token.get();
		IdentityUser user = users.findById(actionToken.getEmail()).orElseThrow();
		user.changePassword(passwordEncoder.encode(PasswordPolicy.requireBcryptCompatible(rawPassword)));
		actionToken.markUsed(Instant.now());
		actionTokens.invalidateUnused(
				user.getEmail(), IdentityActionToken.Purpose.PASSWORD_RESET, Instant.now());
		sessionRevoker.revokeAll(user.getEmail());
		return true;
	}

	private Optional<IdentityActionToken> findUsableTokenForUpdate(
			String rawToken, IdentityActionToken.Purpose purpose) {
		if (rawToken == null || rawToken.isBlank()) {
			return Optional.empty();
		}
		return actionTokens.findByTokenHashForUpdate(hash(rawToken))
				.filter(token -> token.getPurpose() == purpose && token.isUsableAt(Instant.now()));
	}

	private void issueToken(IdentityUser user, IdentityActionToken.Purpose purpose) {
		actionTokens.invalidateUnused(user.getEmail(), purpose, Instant.now());
		byte[] tokenBytes = new byte[32];
		SECURE_RANDOM.nextBytes(tokenBytes);
		String rawToken = Base64.getUrlEncoder().withoutPadding().encodeToString(tokenBytes);
		actionTokens.save(new IdentityActionToken(
				user.getEmail(), hash(rawToken), purpose, Instant.now().plus(ACTION_TOKEN_LIFETIME)));
		eventPublisher.publishEvent(new IdentityEmailRequested(
				user.getEmail(), user.getDisplayName(), rawToken, purpose));
	}

	private static String normalizeEmail(String email) {
		return email.trim().toLowerCase(Locale.ROOT);
	}

	private static String hash(String token) {
		return Sha256Hex.digest(token);
	}

}
