package com.reutevo.oreo;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.mail.MailException;
import org.springframework.stereotype.Component;
import org.springframework.transaction.event.TransactionPhase;
import org.springframework.transaction.event.TransactionalEventListener;

@Component
public class IdentityEmailDispatcher {

	private static final Logger LOGGER = LoggerFactory.getLogger(IdentityEmailDispatcher.class);

	private final IdentityEmailDelivery emailDelivery;

	public IdentityEmailDispatcher(IdentityEmailDelivery emailDelivery) {
		this.emailDelivery = emailDelivery;
	}

	@TransactionalEventListener(phase = TransactionPhase.AFTER_COMMIT)
	public void send(IdentityEmailRequested event) {
		try {
			switch (event.purpose()) {
				case EMAIL_VERIFICATION ->
						emailDelivery.sendVerification(event.email(), event.displayName(), event.token());
				case PASSWORD_RESET ->
						emailDelivery.sendPasswordReset(event.email(), event.displayName(), event.token());
			}
		}
		catch (MailException exception) {
			LOGGER.error("Could not deliver {} account email", event.purpose(), exception);
		}
	}
}
