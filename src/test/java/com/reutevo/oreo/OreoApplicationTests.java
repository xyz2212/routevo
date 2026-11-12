package com.reutevo.oreo;

import java.net.URISyntaxException;
import java.nio.file.Path;
import java.time.Instant;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import jakarta.servlet.http.Cookie;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.context.annotation.Primary;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.mail.MailSendException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@Import({TestcontainersConfiguration.class, OreoApplicationTests.EmailTestConfiguration.class})
@SpringBootTest
@AutoConfigureMockMvc
class OreoApplicationTests {

	private static final String ISSUER = "https://identity.example.test";

	@Autowired
	private MockMvc mockMvc;

	@Autowired
	private JWKSource<SecurityContext> jwkSource;

	@Autowired
	private IdentityUserRepository users;

	@Autowired
	private PasswordEncoder passwordEncoder;

	@Autowired
	private TestIdentityEmailDelivery emailDelivery;

	@DynamicPropertySource
	static void identityProperties(DynamicPropertyRegistry registry) {
		registry.add("identity.issuer-uri", () -> ISSUER);
		registry.add("identity.admin.email", () -> "admin@example.test");
		registry.add("identity.admin.name", () -> "Test Admin");
		registry.add("identity.admin.password", () -> "test-password");
		registry.add("identity.email.from", () -> "no-reply@example.test");
		registry.add("identity.email.frontend-url", () -> "https://app.example.test");
		registry.add("identity.cookie-secure", () -> false);
		registry.add("server.servlet.session.cookie.secure", () -> false);
		registry.add("identity.client.id", () -> "test-client");
		registry.add("identity.client.secret", () -> "test-client-secret");
		registry.add("identity.client.redirect-uri", () -> "https://client.example.test/callback");
		registry.add("identity.signing-key.store", OreoApplicationTests::testKeyStorePath);
		registry.add("identity.signing-key.store-password", () -> "test-only-password");
		registry.add("identity.signing-key.alias", () -> "routevo-test");
	}

	@Test
	void contextLoads() {
	}

	@Test
	void apiRequiresAValidScopedToken() throws Exception {
		mockMvc.perform(get("/api/test"))
				.andExpect(status().isUnauthorized());

		mockMvc.perform(get("/api/test").header("Authorization", "Bearer " + issueToken("openid")))
				.andExpect(status().isForbidden());

		mockMvc.perform(get("/api/test").header("Authorization", "Bearer " + issueToken("api.read")))
				.andExpect(status().isNotFound());
	}

	@Test
	void browserRoutesRedirectUnauthenticatedUsersToLogin() throws Exception {
		mockMvc.perform(get("/"))
				.andExpect(status().is3xxRedirection())
				.andExpect(redirectedUrl("/login"));

		mockMvc.perform(get("/app/"))
				.andExpect(status().isOk());
	}

	@Test
	void customerCanStartRegistrationWithoutAnExistingSession() throws Exception {
		mockMvc.perform(post("/api/auth/register")
						.with(csrf())
						.contentType("application/json")
						.content("""
								{
								  "name": "Alex Customer",
								  "email": "registration@example.test",
								  "password": "CorrectHorseBattery9!"
								}
								"""))
				.andExpect(status().isAccepted());
	}

	@Test
	void registrationRejectsPasswordsThatExceedBcryptUtf8Limit() throws Exception {
		mockMvc.perform(post("/api/auth/register")
						.with(csrf())
						.contentType("application/json")
						.content("""
								{
								  "name": "Unicode Customer",
								  "email": "unicode@example.test",
								  "password": "%s"
								}
								""".formatted("密".repeat(25))))
				.andExpect(status().isBadRequest());
	}

	@Test
	void registrationStillReturnsGenericResponseWhenEmailDeliveryFails() throws Exception {
		emailDelivery.failNextDelivery();
		mockMvc.perform(post("/api/auth/register")
						.with(csrf())
						.contentType("application/json")
						.content("""
								{
								  "name": "Mail Failure",
								  "email": "mail-failure@example.test",
								  "password": "CorrectHorseBattery9!"
								}
								"""))
				.andExpect(status().isAccepted())
				.andExpect(jsonPath("$.message").value(
						"If an account can be registered with that address, a verification email will be sent."));
	}

	@Test
	void customerCanVerifyTheirEmailUsingTheOneTimeLink() throws Exception {
		mockMvc.perform(post("/api/auth/register")
						.with(csrf())
						.contentType("application/json")
						.content("""
								{
								  "name": "Alex Customer",
								  "email": "Alex@Example.Test",
								  "password": "CorrectHorseBattery9!"
								}
								"""))
				.andExpect(status().isAccepted());

		TestIdentityEmailDelivery.DeliveredEmail verification = emailDelivery.lastVerification();
		assertEquals("alex@example.test", verification.email());
		IdentityUser unverifiedUser = users.findById("alex@example.test").orElseThrow();
		assertTrue(unverifiedUser.isEnabled());
		org.junit.jupiter.api.Assertions.assertFalse(unverifiedUser.isEmailVerified());
		mockMvc.perform(post("/login")
						.param("username", "alex@example.test")
						.param("password", "CorrectHorseBattery9!")
						.with(csrf()))
				.andExpect(redirectedUrl("/login?error"));

		mockMvc.perform(post("/api/auth/verify-email")
						.with(csrf())
						.contentType("application/json")
						.content("""
								{"token": "%s"}
								""".formatted(verification.token())))
				.andExpect(status().isOk());

		IdentityUser user = users.findById("alex@example.test").orElseThrow();
		assertTrue(user.isEmailVerified());
		assertTrue(passwordEncoder.matches("CorrectHorseBattery9!", user.getPassword()));
		mockMvc.perform(post("/api/auth/verify-email")
						.with(csrf())
						.contentType("application/json")
						.content("""
								{"token": "%s"}
								""".formatted(verification.token())))
				.andExpect(status().isBadRequest());
		mockMvc.perform(post("/login")
						.param("username", "alex@example.test")
						.param("password", "CorrectHorseBattery9!")
						.with(csrf()))
				.andExpect(redirectedUrl("/"));
	}

	@Test
	void customerCanResetTheirPasswordUsingOneTimeLink() throws Exception {
		mockMvc.perform(post("/api/auth/register")
						.with(csrf())
						.contentType("application/json")
						.content("""
								{
								  "name": "Reset Customer",
								  "email": "reset@example.test",
								  "password": "InitialPassword9!"
								}
								"""))
				.andExpect(status().isAccepted());
		String verificationToken = emailDelivery.lastVerification().token();
		mockMvc.perform(post("/api/auth/verify-email")
						.with(csrf())
						.contentType("application/json")
						.content("""
								{"token": "%s"}
								""".formatted(verificationToken)))
				.andExpect(status().isOk());

		mockMvc.perform(post("/api/auth/forgot-password")
						.with(csrf())
						.contentType("application/json")
						.content("""
								{"email": "reset@example.test"}
								"""))
				.andExpect(status().isAccepted());
		String resetToken = emailDelivery.lastPasswordReset().token();

		mockMvc.perform(post("/api/auth/reset-password")
						.with(csrf())
						.contentType("application/json")
						.content("""
								{"token": "%s", "password": "ChangedPassword9!"}
								""".formatted(resetToken)))
				.andExpect(status().isOk());
		mockMvc.perform(post("/api/auth/reset-password")
						.with(csrf())
						.contentType("application/json")
						.content("""
								{"token": "%s", "password": "ChangedPassword9!"}
								""".formatted(resetToken)))
				.andExpect(status().isBadRequest());
		mockMvc.perform(post("/login")
						.param("username", "reset@example.test")
						.param("password", "ChangedPassword9!")
						.with(csrf()))
				.andExpect(redirectedUrl("/"));
	}

	@Test
	void initialUserIsSeededInTheDatabaseAndCanSignIn() throws Exception {
		IdentityUser user = users.findById("admin@example.test").orElseThrow();
		assertTrue(passwordEncoder.matches("test-password", user.getPassword()));

		mockMvc.perform(post("/login")
						.param("username", "admin@example.test")
						.param("password", "test-password")
						.with(csrf()))
				.andExpect(status().is3xxRedirection());
	}

	@Test
	void browserCanUseTheSessionBffForLoginProfileAndLogout() throws Exception {
		MvcResult csrfResult = mockMvc.perform(get("/api/auth/csrf"))
				.andExpect(status().isOk())
				.andReturn();
		Cookie csrfCookie = csrfResult.getResponse().getCookie("XSRF-TOKEN");
		assertNotNull(csrfCookie);
		String csrfToken = new ObjectMapper().readTree(csrfResult.getResponse().getContentAsString())
				.get("token").asText();
		MvcResult login = mockMvc.perform(post("/api/auth/login")
						.cookie(csrfCookie)
						.header("X-XSRF-TOKEN", csrfToken)
						.contentType("application/json")
						.content("""
								{"email": "admin@example.test", "password": "test-password"}
								"""))
				.andExpect(status().isOk())
				.andReturn();
		MockHttpSession session = (MockHttpSession) login.getRequest().getSession(false);

		mockMvc.perform(get("/api/auth/me").session(session))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.email").value("admin@example.test"))
				.andExpect(jsonPath("$.roles[0]").value("ADMIN"));

		mockMvc.perform(post("/api/auth/logout").with(csrf()).session(session))
				.andExpect(status().isNoContent());
		mockMvc.perform(get("/api/auth/me"))
				.andExpect(status().isUnauthorized());
	}

	@Test
	void passwordRecoveryRequestsAreLimitedByClientIp() throws Exception {
		for (int requestNumber = 0; requestNumber < 30; requestNumber++) {
			mockMvc.perform(post("/api/auth/forgot-password")
							.with(csrf())
							.with(request -> {
								request.setRemoteAddr("192.0.2.45");
								return request;
							})
							.contentType("application/json")
							.content("""
									{"email": "unknown-%d@example.test"}
									""".formatted(requestNumber)))
					.andExpect(status().isAccepted());
		}

		mockMvc.perform(post("/api/auth/forgot-password")
						.with(csrf())
						.with(request -> {
							request.setRemoteAddr("192.0.2.45");
							return request;
						})
						.contentType("application/json")
						.content("""
								{"email": "unknown-final@example.test"}
								"""))
				.andExpect(status().isTooManyRequests());
	}

	@Test
	void passwordResetRevokesExistingBrowserSessions() throws Exception {
		mockMvc.perform(post("/api/auth/register")
						.with(csrf())
						.contentType("application/json")
						.content("""
								{
								  "name": "Session Customer",
								  "email": "session-revoke@example.test",
								  "password": "InitialPassword9!"
								}
								"""))
				.andExpect(status().isAccepted());
		String verificationToken = emailDelivery.lastVerification().token();
		mockMvc.perform(post("/api/auth/verify-email")
						.with(csrf())
						.contentType("application/json")
						.content("""
								{"token": "%s"}
								""".formatted(verificationToken)))
				.andExpect(status().isOk());
		MvcResult login = mockMvc.perform(post("/api/auth/login")
						.with(csrf())
						.contentType("application/json")
						.content("""
								{"email": "session-revoke@example.test", "password": "InitialPassword9!"}
								"""))
				.andExpect(status().isOk())
				.andReturn();
		MockHttpSession session = (MockHttpSession) login.getRequest().getSession(false);

		mockMvc.perform(post("/api/auth/forgot-password")
						.with(csrf())
						.session(session)
						.contentType("application/json")
						.content("""
								{"email": "session-revoke@example.test"}
								"""))
				.andExpect(status().isAccepted());
		String resetToken = emailDelivery.lastPasswordReset().token();
		mockMvc.perform(post("/api/auth/reset-password")
						.with(csrf())
						.session(session)
						.contentType("application/json")
						.content("""
								{"token": "%s", "password": "ChangedPassword9!"}
								""".formatted(resetToken)))
				.andExpect(status().isOk());

		mockMvc.perform(get("/api/auth/me").session(session))
				.andExpect(status().isUnauthorized());
	}

	@Test
	void oidcDiscoveryPublishesTheConfiguredIssuer() throws Exception {
		mockMvc.perform(get("/.well-known/openid-configuration"))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.issuer").value(ISSUER));
	}

	@Test
	void jwksEndpointPublishesOnlyThePublicSigningKey() throws Exception {
		mockMvc.perform(get("/oauth2/jwks"))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.keys[0].d").doesNotExist());
	}

	private String issueToken(String scope) {
		return new NimbusJwtEncoder(jwkSource)
				.encode(JwtEncoderParameters.from(
						JwsHeader.with(SignatureAlgorithm.RS256).build(),
						JwtClaimsSet.builder()
								.issuer(ISSUER)
								.subject("test-user")
								.issuedAt(Instant.now())
								.expiresAt(Instant.now().plusSeconds(60))
								.claim("scope", scope)
								.build()))
				.getTokenValue();
	}

	private static String testKeyStorePath() {
		try {
			return Path.of(OreoApplicationTests.class.getResource("/identity-test.p12").toURI()).toString();
		}
		catch (URISyntaxException exception) {
			throw new IllegalStateException("Could not resolve the test signing keystore", exception);
		}
	}

	@TestConfiguration
	static class EmailTestConfiguration {
		@Bean
		@Primary
		TestIdentityEmailDelivery testIdentityEmailDelivery() {
			return new TestIdentityEmailDelivery();
		}
	}

	static class TestIdentityEmailDelivery implements IdentityEmailDelivery {
		private volatile DeliveredEmail lastVerification;
		private volatile DeliveredEmail lastPasswordReset;
		private volatile boolean failNext;

		@Override
		public void sendVerification(String email, String displayName, String token) {
			if (failNext) {
				failNext = false;
				throw new MailSendException("Test SMTP failure");
			}
			lastVerification = new DeliveredEmail(email, token);
		}

		@Override
		public void sendPasswordReset(String email, String displayName, String token) {
			lastPasswordReset = new DeliveredEmail(email, token);
		}

		DeliveredEmail lastVerification() {
			if (lastVerification == null) {
				throw new AssertionError("No verification email was delivered");
			}
			return lastVerification;
		}

		DeliveredEmail lastPasswordReset() {
			if (lastPasswordReset == null) {
				throw new AssertionError("No password reset email was delivered");
			}
			return lastPasswordReset;
		}

		void failNextDelivery() {
			failNext = true;
		}

		record DeliveredEmail(String email, String token) {
		}
	}
}
