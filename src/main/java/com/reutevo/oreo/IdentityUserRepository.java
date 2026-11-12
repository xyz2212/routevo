package com.reutevo.oreo;

import org.springframework.data.jpa.repository.JpaRepository;

public interface IdentityUserRepository extends JpaRepository<IdentityUser, String> {
	boolean existsByEmail(String email);
}
