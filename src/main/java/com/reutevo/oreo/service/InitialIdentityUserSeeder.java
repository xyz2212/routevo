package com.reutevo.oreo.service;

import com.reutevo.oreo.entity.IdentityUser;
import com.reutevo.oreo.repository.IdentityUserRepository;
import com.reutevo.oreo.common.PasswordPolicy;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.util.Locale;

@Component
public class InitialIdentityUserSeeder implements ApplicationRunner {

	private final IdentityUserRepository users;
	private final PasswordEncoder passwordEncoder;
	private final String username;
	private final String displayName;
	private final String password;

	public InitialIdentityUserSeeder(
			IdentityUserRepository users,
			PasswordEncoder passwordEncoder,
			@Value("${identity.admin.email}") String username,
			@Value("${identity.admin.name}") String displayName,
			@Value("${identity.admin.password}") String password) {
		this.users = users;
		this.passwordEncoder = passwordEncoder;
		this.username = username.trim().toLowerCase(Locale.ROOT);
		this.displayName = displayName;
		this.password = PasswordPolicy.requireBcryptCompatible(password);
	}

	@Override
	public void run(ApplicationArguments args) {
		if (!users.existsById(username)) {
			users.save(IdentityUser.initialAdmin(username, displayName, passwordEncoder.encode(password)));
		}
	}
}
