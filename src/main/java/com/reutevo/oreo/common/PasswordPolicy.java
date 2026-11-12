package com.reutevo.oreo.common;

import java.nio.charset.StandardCharsets;

public final class PasswordPolicy {

	private static final int BCRYPT_MAX_BYTES = 72;

	private PasswordPolicy() {
	}

	public static boolean fitsBcrypt(String password) {
		return password != null && password.getBytes(StandardCharsets.UTF_8).length <= BCRYPT_MAX_BYTES;
	}

	public static String requireBcryptCompatible(String password) {
		if (!fitsBcrypt(password)) {
			throw new IllegalArgumentException("Passwords must be at most 72 UTF-8 bytes");
		}
		return password;
	}
}
