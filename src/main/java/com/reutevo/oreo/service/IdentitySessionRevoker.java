package com.reutevo.oreo.service;

import java.util.Locale;

import org.springframework.security.core.session.SessionInformation;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

@Service
public class IdentitySessionRevoker {

	private final SessionRegistry sessionRegistry;

	public IdentitySessionRevoker(SessionRegistry sessionRegistry) {
		this.sessionRegistry = sessionRegistry;
	}

	public void revokeAll(String email) {
		String normalizedEmail = email.toLowerCase(Locale.ROOT);
		sessionRegistry.getAllPrincipals().stream()
				.filter(UserDetails.class::isInstance)
				.map(UserDetails.class::cast)
				.filter(user -> user.getUsername().equals(normalizedEmail))
				.flatMap(user -> sessionRegistry.getAllSessions(user, false).stream())
				.forEach(SessionInformation::expireNow);
	}
}
