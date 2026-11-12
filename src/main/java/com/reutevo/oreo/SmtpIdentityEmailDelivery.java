package com.reutevo.oreo;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Component;

@Component
public class SmtpIdentityEmailDelivery implements IdentityEmailDelivery {

	private final JavaMailSender mailSender;
	private final String from;
	private final String frontendUrl;

	public SmtpIdentityEmailDelivery(
			JavaMailSender mailSender,
			@Value("${identity.email.from}") String from,
			@Value("${identity.email.frontend-url}") String frontendUrl) {
		this.mailSender = mailSender;
		this.from = from;
		this.frontendUrl = frontendUrl;
	}

	@Override
	public void sendVerification(String email, String displayName, String token) {
		send(email, "Verify your Routevo email", "verify", token);
	}

	@Override
	public void sendPasswordReset(String email, String displayName, String token) {
		send(email, "Reset your Routevo password", "reset", token);
	}

	@Override
	public void sendAdministratorInvitation(String email, String token) {
		send(email, "Your Routevo administrator invitation", "admin-invite", token);
	}

	private void send(String email, String subject, String path, String token) {
		String baseUrl = frontendUrl.endsWith("/")
				? frontendUrl.substring(0, frontendUrl.length() - 1)
				: frontendUrl;
		String url = baseUrl + "/app/#/" + path + "?token=" + token;
		SimpleMailMessage message = new SimpleMailMessage();
		message.setFrom(from);
		message.setTo(email);
		message.setSubject(subject);
		message.setText("Complete this action using the following link:\n\n" + url);
		mailSender.send(message);
	}
}
