package com.reutevo.oreo;

public interface IdentityEmailDelivery {

	void sendVerification(String email, String displayName, String token);

	void sendPasswordReset(String email, String displayName, String token);
}
