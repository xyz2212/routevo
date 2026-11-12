package com.reutevo.oreo;

import com.reutevo.oreo.account.IdentityUser;
import com.reutevo.oreo.account.IdentityUserRepository;
import com.reutevo.oreo.email.IdentityEmailDelivery;
import java.net.URISyntaxException;
import java.nio.file.Path;
import java.nio.ByteBuffer;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import jakarta.servlet.http.Cookie;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.context.annotation.Primary;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.test.context.TestSecurityContextHolder;
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
import org.springframework.test.web.servlet.request.RequestPostProcessor;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
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

	private Cookie apiCsrfCookie;
	private String apiCsrfHeaderName;
	private String apiCsrfToken;

	@BeforeEach
	void initializeApiCsrfToken() throws Exception {
		MvcResult csrfResult = mockMvc.perform(get("/api/auth/csrf"))
				.andExpect(status().isOk())
				.andReturn();
		apiCsrfCookie = csrfResult.getResponse().getCookie("XSRF-TOKEN");
		var csrfResponse = new ObjectMapper().readTree(csrfResult.getResponse().getContentAsString());
		apiCsrfHeaderName = csrfResponse.get("headerName").asText();
		apiCsrfToken = csrfResponse.get("token").asText();
	}

	@AfterEach
	void clearSecurityContextBetweenRequests() {
		SecurityContextHolder.clearContext();
		TestSecurityContextHolder.clearContext();
	}

	@DynamicPropertySource
	static void identityProperties(DynamicPropertyRegistry registry) {
		registry.add("identity.issuer-uri", () -> ISSUER);
		registry.add("identity.admin.email", () -> "admin@example.test");
		registry.add("identity.admin.name", () -> "Test Admin");
		registry.add("identity.admin.password", () -> "test-password");
		registry.add("identity.email.from", () -> "no-reply@example.test");
		registry.add("identity.email.frontend-url", () -> "https://app.example.test");
		registry.add("identity.cookie-secure", () -> false);
		registry.add("identity.mfa.encryption-key", () -> java.util.Base64.getEncoder()
				.encodeToString(new byte[32]));
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
		FormCsrf formCsrf = formCsrf();
		mockMvc.perform(post("/login")
						.param("username", "alex@example.test")
						.param("password", "CorrectHorseBattery9!")
						.session(formCsrf.session())
						.param("_csrf", formCsrf.token()))
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
						.session(formCsrf.session())
						.param("_csrf", formCsrf.token()))
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
		FormCsrf formCsrf = formCsrf();
		mockMvc.perform(post("/login")
						.param("username", "reset@example.test")
						.param("password", "ChangedPassword9!")
						.session(formCsrf.session())
						.param("_csrf", formCsrf.token()))
				.andExpect(redirectedUrl("/"));
	}

	@Test
	void initialUserIsSeededInTheDatabaseAndCanSignIn() throws Exception {
		IdentityUser user = users.findById("admin@example.test").orElseThrow();
		assertTrue(passwordEncoder.matches("test-password", user.getPassword()));

		FormCsrf formCsrf = formCsrf();
		MvcResult formLogin = mockMvc.perform(post("/login")
						.param("username", "admin@example.test")
						.param("password", "test-password")
						.session(formCsrf.session())
						.param("_csrf", formCsrf.token()))
				.andExpect(redirectedUrl("/app/#/login"))
				.andReturn();
		mockMvc.perform(get("/api/auth/me")
						.session((MockHttpSession) formLogin.getRequest().getSession(false)))
				.andExpect(status().isUnauthorized());
	}

	@Test
	void browserCanUseTheSessionBffForLoginProfileAndLogout() throws Exception {
		MockHttpSession browserSession = new MockHttpSession();
		MvcResult csrfResult = mockMvc.perform(get("/api/auth/csrf").session(browserSession))
				.andExpect(status().isOk())
				.andReturn();
		Cookie csrfCookie = csrfResult.getResponse().getCookie("XSRF-TOKEN");
		assertNotNull(csrfCookie);
		String csrfToken = new ObjectMapper().readTree(csrfResult.getResponse().getContentAsString())
				.get("token").asText();
		mockMvc.perform(post("/api/auth/register")
						.cookie(csrfCookie)
						.session(browserSession)
						.header("X-XSRF-TOKEN", csrfToken)
						.contentType("application/json")
						.content("""
								{
								  "name": "BFF Customer",
								  "email": "bff-customer@example.test",
								  "password": "CorrectHorseBattery9!"
								}
								"""))
				.andExpect(status().isAccepted());
		mockMvc.perform(post("/api/auth/verify-email")
						.cookie(csrfCookie)
						.session(browserSession)
						.header("X-XSRF-TOKEN", csrfToken)
						.contentType("application/json")
						.content("""
								{"token": "%s"}
								""".formatted(emailDelivery.lastVerification().token())))
				.andExpect(status().isOk());

		MvcResult login = mockMvc.perform(post("/api/auth/login")
						.cookie(csrfCookie)
						.session(browserSession)
						.header("X-XSRF-TOKEN", csrfToken)
						.contentType("application/json")
						.content("""
								{"email": "bff-customer@example.test", "password": "CorrectHorseBattery9!"}
								"""))
				.andExpect(status().isOk())
				.andReturn();
		MockHttpSession session = (MockHttpSession) login.getRequest().getSession(false);

		mockMvc.perform(get("/api/auth/me").session(session))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.email").value("bff-customer@example.test"))
				.andExpect(jsonPath("$.roles[0]").value("CUSTOMER"))
				.andExpect(jsonPath("$.mfaSetupRequired").value(false));

		mockMvc.perform(post("/api/auth/logout").with(csrf()).session(session))
				.andExpect(status().isNoContent());
		mockMvc.perform(get("/api/auth/me"))
				.andExpect(status().isUnauthorized());
	}

	@Test
	void customerCanApplyAndAdminCanReviewWithoutActivatingDriverAccess() throws Exception {
		mockMvc.perform(post("/api/auth/register")
						.with(csrf())
						.contentType("application/json")
						.content("""
								{
								  "name": "Driver Applicant",
								  "email": "driver-applicant@example.test",
								  "phone": "+852 5555 0101",
								  "password": "CorrectHorseBattery9!"
								}
								"""))
				.andExpect(status().isAccepted());
		mockMvc.perform(post("/api/auth/verify-email")
						.with(csrf())
						.contentType("application/json")
						.content("""
								{"token": "%s"}
								""".formatted(emailDelivery.lastVerification().token())))
				.andExpect(status().isOk());
		MvcResult login = mockMvc.perform(post("/api/auth/login")
						.with(csrf())
						.contentType("application/json")
						.content("""
								{"email": "driver-applicant@example.test", "password": "CorrectHorseBattery9!"}
								"""))
				.andExpect(status().isOk())
				.andReturn();
		MockHttpSession driverSession = (MockHttpSession) login.getRequest().getSession(false);

		MvcResult application = mockMvc.perform(post("/api/auth/driver-application")
						.with(csrf())
						.session(driverSession)
						.contentType("application/json")
						.content("""
								{"vehicleType": "BICYCLE", "serviceArea": "Central and Western"}
								"""))
				.andExpect(status().isAccepted())
				.andExpect(jsonPath("$.status").value("PENDING"))
				.andReturn();
		String applicationId = new ObjectMapper()
				.readTree(application.getResponse().getContentAsString()).get("id").asText();
		mockMvc.perform(post("/api/auth/driver-application")
						.with(csrf())
						.session(driverSession)
						.contentType("application/json")
						.content("""
								{"vehicleType": "BICYCLE", "serviceArea": "Central and Western"}
								"""))
				.andExpect(status().isConflict());

		mockMvc.perform(get("/api/auth/admin/driver-applications")
						.with(user("admin@example.test").roles("ADMIN")))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$[?(@.id == '%s')].applicantEmail".formatted(applicationId))
						.value(org.hamcrest.Matchers.contains("driver-applicant@example.test")));
		mockMvc.perform(get("/api/auth/admin/driver-applications").session(driverSession))
				.andExpect(status().isForbidden());
		mockMvc.perform(post("/api/auth/admin/driver-applications/{id}/review", applicationId)
						.with(csrf())
						.with(user("admin@example.test").roles("ADMIN"))
						.contentType("application/json")
						.content("""
								{"outcome": "NEEDS_INFORMATION"}
								"""))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.status").value("NEEDS_INFORMATION"));
		mockMvc.perform(org.springframework.test.web.servlet.request.MockMvcRequestBuilders
						.put("/api/auth/driver-application")
						.with(csrf())
						.session(driverSession)
						.contentType("application/json")
						.content("""
								{"vehicleType": "MOTORCYCLE", "serviceArea": "Yau Tsim Mong"}
								"""))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.status").value("PENDING"));
		mockMvc.perform(post("/api/auth/admin/driver-applications/{id}/review", applicationId)
						.with(csrf())
						.with(user("admin@example.test").roles("ADMIN"))
						.contentType("application/json")
						.content("""
								{"outcome": "APPROVED_PENDING_LAUNCH_GATES"}
								"""))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.status").value("APPROVED_PENDING_LAUNCH_GATES"));
		mockMvc.perform(post("/api/auth/admin/driver-applications/{id}/review", applicationId)
						.with(csrf())
						.with(user("admin@example.test").roles("ADMIN"))
						.contentType("application/json")
						.content("""
								{"outcome": "REJECTED"}
								"""))
				.andExpect(status().isConflict());

		mockMvc.perform(get("/api/auth/driver-application").session(driverSession))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.status").value("APPROVED_PENDING_LAUNCH_GATES"));
		mockMvc.perform(get("/api/auth/me").session(driverSession))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.roles").value(org.hamcrest.Matchers.contains("CUSTOMER")));
	}

	@Test
	void invitedAdministratorMustAcceptInvitationAndEnrollMfaBeforeAdminAccess() throws Exception {
		mockMvc.perform(post("/api/auth/admin/invitations")
						.with(csrf())
						.with(user("admin@example.test").roles("ADMIN"))
						.contentType("application/json")
						.content("""
								{"email": "invited-admin@example.test"}
								"""))
				.andExpect(status().isAccepted());

		String invitationToken = emailDelivery.lastAdminInvitation().token();
		mockMvc.perform(post("/api/auth/admin/invitations")
						.with(csrf())
						.with(user("admin@example.test").roles("ADMIN"))
						.contentType("application/json")
						.content("""
								{"email": "admin@example.test"}
								"""))
				.andExpect(status().isConflict())
				.andExpect(jsonPath("$.message").value("An account already uses this email address."));
		mockMvc.perform(post("/api/auth/admin/invitations")
						.with(csrf())
						.contentType("application/json")
						.content("""
								{"email": "public@example.test"}
								"""))
				.andExpect(status().isUnauthorized());
		mockMvc.perform(post("/api/auth/accept-admin-invitation")
						.with(csrf())
						.contentType("application/json")
						.content("""
								{
								  "token": "%s",
								  "name": "Invited Admin",
								  "password": "InvitedAdminPassword9!"
								}
								""".formatted(invitationToken)))
				.andExpect(status().isOk());
		mockMvc.perform(post("/api/auth/accept-admin-invitation")
						.with(csrf())
						.contentType("application/json")
						.content("""
								{
								  "token": "%s",
								  "name": "Invited Admin",
								  "password": "InvitedAdminPassword9!"
								}
								""".formatted(invitationToken)))
				.andExpect(status().isBadRequest());

		MvcResult setupLogin = mockMvc.perform(post("/api/auth/login")
						.with(csrf())
						.contentType("application/json")
						.content("""
								{"email": "invited-admin@example.test", "password": "InvitedAdminPassword9!"}
								"""))
				.andExpect(status().isAccepted())
				.andExpect(jsonPath("$.stage").value("MFA_SETUP_REQUIRED"))
				.andReturn();
		MockHttpSession setupSession = (MockHttpSession) setupLogin.getRequest().getSession(false);
		mockMvc.perform(get("/api/auth/me").session(setupSession))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.roles.length()").value(0));
	}

	@Test
	void administratorMustEnrollAndVerifyTotpBeforeReceivingAnAdminSession() throws Exception {
		MvcResult setupLogin = mockMvc.perform(post("/api/auth/login")
						.with(csrf())
						.contentType("application/json")
						.content("""
								{"email": "admin@example.test", "password": "test-password"}
								"""))
				.andExpect(status().isAccepted())
				.andExpect(jsonPath("$.stage").value("MFA_SETUP_REQUIRED"))
				.andReturn();
		MockHttpSession setupSession = (MockHttpSession) setupLogin.getRequest().getSession(false);
		mockMvc.perform(get("/api/auth/me").session(setupSession))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.roles.length()").value(0))
				.andExpect(jsonPath("$.mfaSetupRequired").value(true));

		MvcResult enrollment = mockMvc.perform(post("/api/auth/mfa/enrollment")
						.with(csrf())
						.session(setupSession))
				.andExpect(status().isOk())
				.andReturn();
		String secret = new ObjectMapper().readTree(enrollment.getResponse().getContentAsString())
				.get("secret").asText();
		String setupCode = totp(secret, Instant.now());
		MvcResult enrolled = mockMvc.perform(post("/api/auth/mfa/enrollment/confirm")
						.with(csrf())
						.session(setupSession)
						.contentType("application/json")
						.content("""
								{"code": "%s"}
								""".formatted(setupCode)))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.recoveryCodes.length()").value(10))
				.andReturn();
		String recoveryCode = new ObjectMapper().readTree(enrolled.getResponse().getContentAsString())
				.get("recoveryCodes").get(0).asText();

		MvcResult mfaLogin = mockMvc.perform(post("/api/auth/login")
						.with(csrf())
						.contentType("application/json")
						.content("""
								{"email": "admin@example.test", "password": "test-password"}
								"""))
				.andExpect(status().isAccepted())
				.andExpect(jsonPath("$.stage").value("MFA_REQUIRED"))
				.andReturn();
		MockHttpSession mfaSession = (MockHttpSession) mfaLogin.getRequest().getSession(false);
		mockMvc.perform(get("/api/auth/me").session(mfaSession))
				.andExpect(status().isUnauthorized());

		mockMvc.perform(post("/api/auth/mfa/verify")
						.with(csrf())
						.session(mfaSession)
						.contentType("application/json")
						.content("""
								{"code": "%s"}
								""".formatted(totp(secret, Instant.now()))))
				.andExpect(status().isOk());
		mockMvc.perform(get("/api/auth/me").session(mfaSession))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.roles[0]").value("ADMIN"));

		mockMvc.perform(post("/api/auth/logout").with(csrf()).session(mfaSession))
				.andExpect(status().isNoContent());
		MvcResult recoveryLogin = mockMvc.perform(post("/api/auth/login")
						.with(csrf())
						.contentType("application/json")
						.content("""
								{"email": "admin@example.test", "password": "test-password"}
								"""))
				.andExpect(status().isAccepted())
				.andReturn();
		MockHttpSession recoverySession = (MockHttpSession) recoveryLogin.getRequest().getSession(false);
		mockMvc.perform(post("/api/auth/mfa/verify")
						.with(csrf())
						.session(recoverySession)
						.contentType("application/json")
						.content("""
								{"code": "%s"}
								""".formatted(recoveryCode)))
				.andExpect(status().isOk());

		MvcResult replayLogin = mockMvc.perform(post("/api/auth/login")
						.with(csrf())
						.contentType("application/json")
						.content("""
								{"email": "admin@example.test", "password": "test-password"}
								"""))
				.andExpect(status().isAccepted())
				.andReturn();
		MockHttpSession replaySession = (MockHttpSession) replayLogin.getRequest().getSession(false);
		mockMvc.perform(post("/api/auth/mfa/verify")
						.with(csrf())
						.session(replaySession)
						.contentType("application/json")
						.content("""
								{"code": "%s"}
								""".formatted(recoveryCode)))
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

	private RequestPostProcessor csrf() {
		return request -> {
			request.setCookies(apiCsrfCookie);
			request.addHeader(apiCsrfHeaderName, apiCsrfToken);
			return request;
		};
	}

	private FormCsrf formCsrf() throws Exception {
		MvcResult result = mockMvc.perform(get("/login"))
				.andExpect(status().isOk())
				.andReturn();
		java.util.regex.Matcher matcher = java.util.regex.Pattern
				.compile("name=\"_csrf\"[^>]*value=\"([^\"]+)\"")
				.matcher(result.getResponse().getContentAsString());
		assertTrue(matcher.find(), "The login page should expose its session CSRF token.");
		return new FormCsrf((MockHttpSession) result.getRequest().getSession(false), matcher.group(1));
	}

	private record FormCsrf(MockHttpSession session, String token) {
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

	private static String totp(String base32Secret, Instant now) throws Exception {
		String alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
		String normalized = base32Secret.replace("=", "").toUpperCase(java.util.Locale.ROOT);
		List<Byte> secretBytes = new ArrayList<>();
		int buffer = 0;
		int bits = 0;
		for (char character : normalized.toCharArray()) {
			buffer = (buffer << 5) | alphabet.indexOf(character);
			bits += 5;
			if (bits >= 8) {
				secretBytes.add((byte) (buffer >> (bits - 8)));
				bits -= 8;
			}
		}
		byte[] counter = ByteBuffer.allocate(Long.BYTES).putLong(now.getEpochSecond() / 30).array();
		Mac hmac = Mac.getInstance("HmacSHA1");
		hmac.init(new SecretKeySpec(toByteArray(secretBytes), "HmacSHA1"));
		byte[] digest = hmac.doFinal(counter);
		int offset = digest[digest.length - 1] & 0x0f;
		int binary = ((digest[offset] & 0x7f) << 24)
				| ((digest[offset + 1] & 0xff) << 16)
				| ((digest[offset + 2] & 0xff) << 8)
				| (digest[offset + 3] & 0xff);
		return "%06d".formatted(binary % 1_000_000);
	}

	private static byte[] toByteArray(List<Byte> values) {
		byte[] bytes = new byte[values.size()];
		for (int index = 0; index < values.size(); index++) {
			bytes[index] = values.get(index);
		}
		return bytes;
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
		private volatile DeliveredEmail lastAdminInvitation;
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

		@Override
		public void sendAdministratorInvitation(String email, String token) {
			lastAdminInvitation = new DeliveredEmail(email, token);
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

		DeliveredEmail lastAdminInvitation() {
			if (lastAdminInvitation == null) {
				throw new AssertionError("No administrator invitation was delivered");
			}
			return lastAdminInvitation;
		}

		void failNextDelivery() {
			failNext = true;
		}

		record DeliveredEmail(String email, String token) {
		}
	}
}
