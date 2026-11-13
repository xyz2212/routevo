package com.reutevo.oreo.email;

import com.reutevo.oreo.entity.IdentityActionToken;

public record IdentityEmailRequested(
		String email,
		String displayName,
		String token,
		IdentityActionToken.Purpose purpose) {
}
