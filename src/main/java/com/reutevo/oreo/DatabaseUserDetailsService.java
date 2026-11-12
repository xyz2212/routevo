package com.reutevo.oreo;

import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Locale;

@Service
public class DatabaseUserDetailsService implements UserDetailsService {

	private final IdentityUserRepository users;

	public DatabaseUserDetailsService(IdentityUserRepository users) {
		this.users = users;
	}

	@Override
	@Transactional(readOnly = true)
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		IdentityUser identityUser = users.findById(username.trim().toLowerCase(Locale.ROOT))
				.orElseThrow(() -> new UsernameNotFoundException("User not found"));

		return User.withUsername(identityUser.getUsername())
				.password(identityUser.getPassword())
				.disabled(!identityUser.isEnabled() || !identityUser.isEmailVerified())
				.authorities(AuthorityUtils.createAuthorityList(
						identityUser.getRoles().stream().map(role -> "ROLE_" + role.name()).toList()))
				.build();
	}
}
