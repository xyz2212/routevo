package com.reutevo.oreo;

import java.time.Instant;
import java.util.List;
import java.util.Locale;
import java.util.UUID;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import jakarta.validation.Valid;
import jakarta.validation.constraints.AssertTrue;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/auth")
public class IdentityAccountController {

	private static final String MFA_LOGIN_EMAIL = "routevo.admin.mfa.email";
	private static final String MFA_LOGIN_EXPIRES_AT = "routevo.admin.mfa.expiresAt";
	private static final String MFA_SETUP_REQUIRED = "MFA_SETUP_REQUIRED";

	private final IdentityAccountService accounts;
	private final IdentityUserRepository users;
	private final IdentityMfaService mfa;
	private final IdentityDriverApplicationService driverApplications;
	private final IdentityAdminInvitationService adminInvitations;
	private final DatabaseUserDetailsService userDetailsService;
	private final AuthenticationManager authenticationManager;
	private final SecurityContextRepository securityContextRepository;
	private final IdentityRateLimitService rateLimits;
	private final SessionAuthenticationStrategy sessionAuthenticationStrategy;
	private final SessionRegistry sessionRegistry;

	public IdentityAccountController(
			IdentityAccountService accounts,
			IdentityUserRepository users,
			IdentityMfaService mfa,
			IdentityDriverApplicationService driverApplications,
			IdentityAdminInvitationService adminInvitations,
			DatabaseUserDetailsService userDetailsService,
			AuthenticationConfiguration authenticationConfiguration,
			SecurityContextRepository securityContextRepository,
			IdentityRateLimitService rateLimits,
			SessionAuthenticationStrategy sessionAuthenticationStrategy,
			SessionRegistry sessionRegistry) throws Exception {
		this.accounts = accounts;
		this.users = users;
		this.mfa = mfa;
		this.driverApplications = driverApplications;
		this.adminInvitations = adminInvitations;
		this.userDetailsService = userDetailsService;
		this.authenticationManager = authenticationConfiguration.getAuthenticationManager();
		this.securityContextRepository = securityContextRepository;
		this.rateLimits = rateLimits;
		this.sessionAuthenticationStrategy = sessionAuthenticationStrategy;
		this.sessionRegistry = sessionRegistry;
	}

	@GetMapping("/csrf")
	public CsrfResponse csrf(CsrfToken csrfToken) {
		return new CsrfResponse(csrfToken.getHeaderName(), csrfToken.getToken());
	}

	@PostMapping("/login")
	public ResponseEntity<?> login(
			@Valid @RequestBody LoginRequest request,
			HttpServletRequest servletRequest,
			HttpServletResponse servletResponse) {
		if (!rateLimits.allow("login", request.email(), remoteAddress(servletRequest))) {
			return rateLimited();
		}
		if (!PasswordPolicy.fitsBcrypt(request.password())) {
			return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
					.body(new GenericMessage("Email or password is incorrect."));
		}
		Authentication authentication;
		try {
			authentication = authenticationManager.authenticate(
					UsernamePasswordAuthenticationToken.unauthenticated(
							request.email().trim().toLowerCase(Locale.ROOT), request.password()));
		}
		catch (AuthenticationException exception) {
			return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
					.body(new GenericMessage("Email or password is incorrect."));
		}

		IdentityUser identityUser = users.findById(authentication.getName()).orElseThrow();
		if (identityUser.getRoles().contains(IdentityRole.ADMIN)) {
			Authentication current = SecurityContextHolder.getContext().getAuthentication();
			if (current != null && current.isAuthenticated()
					&& identityUser.getEmail().equals(current.getName())) {
				boolean adminAuthenticated = current.getAuthorities().stream()
						.anyMatch(authority -> authority.getAuthority().equals("ROLE_ADMIN"));
				if (adminAuthenticated) {
					return ResponseEntity.ok(new LoginResult("AUTHENTICATED", "Signed in."));
				}
				if (current.getAuthorities().stream()
						.anyMatch(authority -> authority.getAuthority().equals(MFA_SETUP_REQUIRED))) {
					return ResponseEntity.accepted().body(new LoginResult(
							MFA_SETUP_REQUIRED, "Set up an authenticator before continuing."));
				}
			}
			if (!identityUser.isMfaEnabled()) {
				Authentication setupAuthentication = UsernamePasswordAuthenticationToken.authenticated(
						authentication.getPrincipal(), null,
						AuthorityUtils.createAuthorityList(MFA_SETUP_REQUIRED));
				sessionAuthenticationStrategy.onAuthentication(
						setupAuthentication, servletRequest, servletResponse);
				saveAuthentication(setupAuthentication, servletRequest, servletResponse);
				return ResponseEntity.accepted().body(new LoginResult(
						MFA_SETUP_REQUIRED, "Set up an authenticator before continuing."));
			}
			return startMfaLogin(identityUser.getEmail(), servletRequest, servletResponse);
		}

		sessionAuthenticationStrategy.onAuthentication(authentication, servletRequest, servletResponse);
		saveAuthentication(authentication, servletRequest, servletResponse);
		return ResponseEntity.ok(new LoginResult("AUTHENTICATED", "Signed in."));
	}

	@PostMapping("/mfa/enrollment")
	public ResponseEntity<?> beginMfaEnrollment(
			Authentication authentication, HttpServletRequest servletRequest) {
		if (!rateLimits.allow("mfa-enrollment", authentication.getName(), remoteAddress(servletRequest))) {
			return rateLimited();
		}
		return ResponseEntity.ok(mfa.beginEnrollment(authentication.getName()));
	}

	@PostMapping("/mfa/enrollment/confirm")
	public ResponseEntity<?> confirmMfaEnrollment(
			@Valid @RequestBody MfaCodeRequest request,
			Authentication authentication,
			HttpServletRequest servletRequest,
			HttpServletResponse servletResponse) {
		if (!rateLimits.allow("mfa-enrollment-confirm", authentication.getName(),
				remoteAddress(servletRequest))) {
			return rateLimited();
		}
		var recoveryCodes = mfa.confirmEnrollment(authentication.getName(), request.code());
		if (recoveryCodes.isEmpty()) {
			return ResponseEntity.badRequest().body(new GenericMessage(
					"The authenticator code is invalid or expired."));
		}
		SecurityContextHolder.clearContext();
		securityContextRepository.saveContext(
				SecurityContextHolder.createEmptyContext(), servletRequest, servletResponse);
		HttpSession session = servletRequest.getSession(false);
		if (session != null) {
			session.invalidate();
		}
		return ResponseEntity.ok(new MfaEnrollmentResult(
				recoveryCodes.get(), "Save these recovery codes now. Sign in again to continue."));
	}

	@PostMapping("/mfa/verify")
	public ResponseEntity<?> verifyMfa(
			@Valid @RequestBody MfaCodeRequest request,
			HttpServletRequest servletRequest,
			HttpServletResponse servletResponse) {
		HttpSession session = servletRequest.getSession(false);
		if (session == null) {
			if (!rateLimits.allow("mfa-login", null, remoteAddress(servletRequest))) {
				return rateLimited();
			}
			return mfaRequired();
		}
		Object emailValue = session.getAttribute(MFA_LOGIN_EMAIL);
		Object expiryValue = session.getAttribute(MFA_LOGIN_EXPIRES_AT);
		if (!(emailValue instanceof String email)
				|| !(expiryValue instanceof Instant expiresAt)
				|| !expiresAt.isAfter(Instant.now())) {
			session.removeAttribute(MFA_LOGIN_EMAIL);
			session.removeAttribute(MFA_LOGIN_EXPIRES_AT);
			if (!rateLimits.allow("mfa-login", null, remoteAddress(servletRequest))) {
				return rateLimited();
			}
			return mfaRequired();
		}
		if (!rateLimits.allow("mfa-login", email, remoteAddress(servletRequest))) {
			return rateLimited();
		}
		if (!mfa.verifyLogin(email, request.code())) {
			return mfaRequired();
		}
		session.removeAttribute(MFA_LOGIN_EMAIL);
		session.removeAttribute(MFA_LOGIN_EXPIRES_AT);
		UserDetails userDetails = userDetailsService.loadUserByUsername(email);
		Authentication mfaAuthentication = UsernamePasswordAuthenticationToken.authenticated(
				userDetails, null, userDetails.getAuthorities());
		sessionAuthenticationStrategy.onAuthentication(mfaAuthentication, servletRequest, servletResponse);
		saveAuthentication(mfaAuthentication, servletRequest, servletResponse);
		return ResponseEntity.ok(new LoginResult("AUTHENTICATED", "Signed in."));
	}

	private ResponseEntity<LoginResult> startMfaLogin(
			String email,
			HttpServletRequest servletRequest,
			HttpServletResponse servletResponse) {
		HttpSession existingSession = servletRequest.getSession(false);
		if (existingSession != null) {
			sessionRegistry.removeSessionInformation(existingSession.getId());
			servletRequest.changeSessionId();
		}
		SecurityContextHolder.clearContext();
		securityContextRepository.saveContext(
				SecurityContextHolder.createEmptyContext(), servletRequest, servletResponse);
		HttpSession session = servletRequest.getSession(true);
		session.setAttribute(MFA_LOGIN_EMAIL, email);
		session.setAttribute(MFA_LOGIN_EXPIRES_AT, Instant.now().plusSeconds(300));
		return ResponseEntity.accepted()
				.body(new LoginResult("MFA_REQUIRED", "Enter an authenticator or recovery code."));
	}

	private void saveAuthentication(
			Authentication authentication,
			HttpServletRequest servletRequest,
			HttpServletResponse servletResponse) {
		SecurityContext context = SecurityContextHolder.createEmptyContext();
		context.setAuthentication(authentication);
		SecurityContextHolder.setContext(context);
		securityContextRepository.saveContext(context, servletRequest, servletResponse);
	}

	@GetMapping("/me")
	public UserProfile currentUser(Authentication authentication) {
		IdentityUser user = users.findById(authentication.getName()).orElseThrow();
		List<String> roles = authentication.getAuthorities().stream()
				.map(authority -> authority.getAuthority())
				.filter(authority -> authority.startsWith("ROLE_"))
				.map(authority -> authority.substring("ROLE_".length()))
				.sorted()
				.toList();
		boolean mfaSetupRequired = authentication.getAuthorities().stream()
				.anyMatch(authority -> authority.getAuthority().equals(MFA_SETUP_REQUIRED));
		return new UserProfile(user.getEmail(), user.getDisplayName(), user.getPhone(), roles, mfaSetupRequired);
	}

	@PostMapping("/driver-application")
	public ResponseEntity<IdentityDriverApplicationService.DriverApplicationView> submitDriverApplication(
			@Valid @RequestBody IdentityDriverApplicationService.DriverApplicationRequest request,
			Authentication authentication) {
		return ResponseEntity.accepted()
				.body(driverApplications.submit(authentication.getName(), request));
	}

	@GetMapping("/driver-application")
	public ResponseEntity<IdentityDriverApplicationService.DriverApplicationView> driverApplication(
			Authentication authentication) {
		IdentityDriverApplicationService.DriverApplicationView application =
				driverApplications.findByApplicant(authentication.getName());
		return application == null ? ResponseEntity.noContent().build() : ResponseEntity.ok(application);
	}

	@PutMapping("/driver-application")
	public IdentityDriverApplicationService.DriverApplicationView updateDriverApplication(
			@Valid @RequestBody IdentityDriverApplicationService.DriverApplicationRequest request,
			Authentication authentication) {
		return driverApplications.updateAfterInformationRequest(authentication.getName(), request);
	}

	@GetMapping("/admin/driver-applications")
	public List<IdentityDriverApplicationService.DriverApplicationView> driverApplicationsForReview() {
		return driverApplications.findAllForReview();
	}

	@PostMapping("/admin/driver-applications/{id}/review")
	public IdentityDriverApplicationService.DriverApplicationView reviewDriverApplication(
			@PathVariable UUID id,
			@Valid @RequestBody IdentityDriverApplicationService.DriverApplicationReviewRequest request,
			Authentication authentication) {
		return driverApplications.review(id, request.outcome(), authentication.getName());
	}

	@PostMapping("/admin/invitations")
	public ResponseEntity<GenericMessage> inviteAdministrator(
			@Valid @RequestBody AdminInvitationRequest request,
			Authentication authentication,
			HttpServletRequest servletRequest) {
		if (!rateLimits.allow("admin-invitation", request.email(), remoteAddress(servletRequest))) {
			return rateLimited();
		}
		if (!adminInvitations.invite(request.email())) {
			return ResponseEntity.status(HttpStatus.CONFLICT)
					.body(new GenericMessage("An account already uses this email address."));
		}
		return ResponseEntity.accepted().body(new GenericMessage("The administrator invitation has been sent."));
	}

	@PostMapping("/accept-admin-invitation")
	public ResponseEntity<GenericMessage> acceptAdministratorInvitation(
			@Valid @RequestBody AdminInvitationAcceptanceRequest request,
			HttpServletRequest servletRequest) {
		if (!rateLimits.allow("accept-admin-invitation", null, remoteAddress(servletRequest))) {
			return rateLimited();
		}
		if (!adminInvitations.accept(request.token(), request.name(), request.password())) {
			return ResponseEntity.badRequest()
					.body(new GenericMessage("The administrator invitation is invalid or expired."));
		}
		return ResponseEntity.ok(new GenericMessage("Administrator account created. Sign in to set up MFA."));
	}

	@PostMapping("/register")
	public ResponseEntity<GenericMessage> register(
			@Valid @RequestBody RegistrationRequest request, HttpServletRequest servletRequest) {
		if (!rateLimits.allow("register", request.email(), remoteAddress(servletRequest))) {
			return rateLimited();
		}
		accounts.register(request.email(), request.name(), request.phone(), request.password());
		return ResponseEntity.accepted().body(new GenericMessage(
				"If an account can be registered with that address, a verification email will be sent."));
	}

	@PostMapping("/verify-email")
	public ResponseEntity<GenericMessage> verifyEmail(
			@Valid @RequestBody TokenRequest request, HttpServletRequest servletRequest) {
		if (!rateLimits.allow("verify", null, remoteAddress(servletRequest))) {
			return rateLimited();
		}
		if (!accounts.verifyEmail(request.token())) {
			return ResponseEntity.status(HttpStatus.BAD_REQUEST)
					.body(new GenericMessage("The verification link is invalid or expired."));
		}
		return ResponseEntity.ok(new GenericMessage("Email verified."));
	}

	@PostMapping("/resend-verification")
	public ResponseEntity<GenericMessage> resendVerification(
			@Valid @RequestBody EmailRequest request, HttpServletRequest servletRequest) {
		if (!rateLimits.allow("resend", request.email(), remoteAddress(servletRequest))) {
			return rateLimited();
		}
		accounts.resendVerification(request.email());
		return ResponseEntity.accepted().body(new GenericMessage(
				"If the address belongs to an unverified account, a verification email will be sent."));
	}

	@PostMapping("/forgot-password")
	public ResponseEntity<GenericMessage> forgotPassword(
			@Valid @RequestBody EmailRequest request, HttpServletRequest servletRequest) {
		if (!rateLimits.allow("forgot", request.email(), remoteAddress(servletRequest))) {
			return rateLimited();
		}
		accounts.requestPasswordReset(request.email());
		return ResponseEntity.accepted().body(new GenericMessage(
				"If an account exists for that address, a password reset email will be sent."));
	}

	@PostMapping("/reset-password")
	public ResponseEntity<GenericMessage> resetPassword(
			@Valid @RequestBody ResetPasswordRequest request, HttpServletRequest servletRequest) {
		if (!rateLimits.allow("reset", null, remoteAddress(servletRequest))) {
			return rateLimited();
		}
		if (!accounts.resetPassword(request.token(), request.password())) {
			return ResponseEntity.status(HttpStatus.BAD_REQUEST)
					.body(new GenericMessage("The reset link is invalid or expired."));
		}
		return ResponseEntity.ok(new GenericMessage("Password reset."));
	}

	public record RegistrationRequest(
			@NotBlank @Size(max = 120) String name,
			@NotBlank @Email @Size(max = 254) String email,
			@Size(max = 32) String phone,
			@NotBlank @Size(min = 12, max = 72) String password) {
		@AssertTrue(message = "Password exceeds the supported UTF-8 byte limit")
		public boolean isPasswordWithinBcryptLimit() {
			return PasswordPolicy.fitsBcrypt(password);
		}
	}

	public record LoginRequest(
			@NotBlank @Email @Size(max = 254) String email,
			@NotBlank @Size(max = 72) String password) {
	}

	public record MfaCodeRequest(@NotBlank @Size(max = 32) String code) {
	}

	public record TokenRequest(@NotBlank String token) {
	}

	public record EmailRequest(@NotBlank @Email @Size(max = 254) String email) {
	}

	public record ResetPasswordRequest(
			@NotBlank String token,
			@NotBlank @Size(min = 12, max = 72) String password) {
		@AssertTrue(message = "Password exceeds the supported UTF-8 byte limit")
		public boolean isPasswordWithinBcryptLimit() {
			return PasswordPolicy.fitsBcrypt(password);
		}
	}

	public record AdminInvitationRequest(
			@NotBlank @Email @Size(max = 254) String email) {
	}

	public record AdminInvitationAcceptanceRequest(
			@NotBlank String token,
			@NotBlank @Size(max = 120) String name,
			@NotBlank @Size(min = 12, max = 72) String password) {
		@AssertTrue(message = "Password exceeds the supported UTF-8 byte limit")
		public boolean isPasswordWithinBcryptLimit() {
			return PasswordPolicy.fitsBcrypt(password);
		}
	}

	public record GenericMessage(String message) {
	}

	public record LoginResult(String stage, String message) {
	}

	public record MfaEnrollmentResult(List<String> recoveryCodes, String message) {
	}

	public record CsrfResponse(String headerName, String token) {
	}

	public record UserProfile(
			String email, String name, String phone, List<String> roles, boolean mfaSetupRequired) {
	}

	private static ResponseEntity<GenericMessage> rateLimited() {
		return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS)
				.body(new GenericMessage("Too many requests. Please try again later."));
	}

	private static ResponseEntity<GenericMessage> mfaRequired() {
		return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
				.body(new GenericMessage("The MFA code is invalid or the challenge has expired."));
	}

	private static String remoteAddress(HttpServletRequest request) {
		String remoteAddress = request.getRemoteAddr();
		return remoteAddress == null ? "unknown" : remoteAddress;
	}
}
