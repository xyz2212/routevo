package com.reutevo.oreo.email;

public interface IdentityEmailDelivery {

	void sendVerification(String email, String displayName, String token);

	void sendPasswordReset(String email, String displayName, String token);

	void sendAdministratorInvitation(String email, String token);
}
