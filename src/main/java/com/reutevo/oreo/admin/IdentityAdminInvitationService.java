package com.reutevo.oreo.admin;

import com.reutevo.oreo.account.IdentityActionToken;
import com.reutevo.oreo.account.IdentityUser;
import com.reutevo.oreo.account.IdentityUserRepository;
import com.reutevo.oreo.common.PasswordPolicy;
import com.reutevo.oreo.common.Sha256Hex;
import com.reutevo.oreo.email.IdentityEmailRequested;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Locale;
import java.util.Optional;

import org.springframework.context.ApplicationEventPublisher;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class IdentityAdminInvitationService {

	private static final Duration INVITATION_LIFETIME = Duration.ofHours(1);
	private static final SecureRandom SECURE_RANDOM = new SecureRandom();

	private final IdentityAdminInvitationRepository invitations;
	private final IdentityUserRepository users;
	private final PasswordEncoder passwordEncoder;
	private final ApplicationEventPublisher eventPublisher;

	public IdentityAdminInvitationService(
			IdentityAdminInvitationRepository invitations,
			IdentityUserRepository users,
			PasswordEncoder passwordEncoder,
			ApplicationEventPublisher eventPublisher) {
		this.invitations = invitations;
		this.users = users;
		this.passwordEncoder = passwordEncoder;
		this.eventPublisher = eventPublisher;
	}

	@Transactional
	public boolean invite(String email) {
		String normalizedEmail = normalizeEmail(email);
		if (users.existsById(normalizedEmail)) {
			return false;
		}

		String token = createToken();
		Instant expiresAt = Instant.now().plus(INVITATION_LIFETIME);
		IdentityAdminInvitation invitation = invitations.findByEmailForUpdate(normalizedEmail)
				.orElseGet(() -> new IdentityAdminInvitation(normalizedEmail, hash(token), expiresAt));
		invitation.issue(hash(token), expiresAt);
		invitations.save(invitation);
		eventPublisher.publishEvent(new IdentityEmailRequested(
				normalizedEmail, normalizedEmail, token, IdentityActionToken.Purpose.ADMIN_INVITATION));
		return true;
	}

	@Transactional
	public boolean accept(String rawToken, String displayName, String rawPassword) {
		if (rawToken == null || rawToken.isBlank()) {
			return false;
		}
		Optional<IdentityAdminInvitation> matchingInvitation = invitations.findByTokenHashForUpdate(hash(rawToken))
				.filter(invitation -> invitation.isUsableAt(Instant.now()));
		if (matchingInvitation.isEmpty()) {
			return false;
		}

		IdentityAdminInvitation invitation = matchingInvitation.get();
		if (users.existsById(invitation.getEmail())) {
			return false;
		}
		IdentityUser administrator = IdentityUser.invitedAdministrator(
				invitation.getEmail(),
				displayName.trim(),
				passwordEncoder.encode(PasswordPolicy.requireBcryptCompatible(rawPassword)));
		users.save(administrator);
		invitation.accept(Instant.now());
		return true;
	}

	private static String createToken() {
		byte[] tokenBytes = new byte[32];
		SECURE_RANDOM.nextBytes(tokenBytes);
		return Base64.getUrlEncoder().withoutPadding().encodeToString(tokenBytes);
	}

	private static String hash(String token) {
		return Sha256Hex.digest(token);
	}

	private static String normalizeEmail(String email) {
		return email.trim().toLowerCase(Locale.ROOT);
	}
}
