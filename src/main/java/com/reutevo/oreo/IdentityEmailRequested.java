package com.reutevo.oreo;

public record IdentityEmailRequested(
		String email,
		String displayName,
		String token,
		IdentityActionToken.Purpose purpose) {
}
