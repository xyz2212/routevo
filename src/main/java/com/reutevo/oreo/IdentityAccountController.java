package com.reutevo.oreo;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
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
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/auth")
public class IdentityAccountController {

	private final IdentityAccountService accounts;
	private final IdentityUserRepository users;
	private final AuthenticationManager authenticationManager;
	private final SecurityContextRepository securityContextRepository;
	private final IdentityRateLimitService rateLimits;
	private final SessionAuthenticationStrategy sessionAuthenticationStrategy;

	public IdentityAccountController(
			IdentityAccountService accounts,
			IdentityUserRepository users,
			AuthenticationConfiguration authenticationConfiguration,
			SecurityContextRepository securityContextRepository,
			IdentityRateLimitService rateLimits,
			SessionAuthenticationStrategy sessionAuthenticationStrategy) throws Exception {
		this.accounts = accounts;
		this.users = users;
		this.authenticationManager = authenticationConfiguration.getAuthenticationManager();
		this.securityContextRepository = securityContextRepository;
		this.rateLimits = rateLimits;
		this.sessionAuthenticationStrategy = sessionAuthenticationStrategy;
	}

	@GetMapping("/csrf")
	public CsrfResponse csrf(CsrfToken csrfToken) {
		return new CsrfResponse(csrfToken.getHeaderName(), csrfToken.getToken());
	}

	@PostMapping("/login")
	public ResponseEntity<GenericMessage> login(
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
							request.email().trim().toLowerCase(java.util.Locale.ROOT), request.password()));
		}
		catch (AuthenticationException exception) {
			return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
					.body(new GenericMessage("Email or password is incorrect."));
		}

		sessionAuthenticationStrategy.onAuthentication(authentication, servletRequest, servletResponse);
		SecurityContext context = SecurityContextHolder.createEmptyContext();
		context.setAuthentication(authentication);
		SecurityContextHolder.setContext(context);
		securityContextRepository.saveContext(context, servletRequest, servletResponse);
		return ResponseEntity.ok(new GenericMessage("Signed in."));
	}

	@GetMapping("/me")
	public UserProfile currentUser(Authentication authentication) {
		IdentityUser user = users.findById(authentication.getName()).orElseThrow();
		return new UserProfile(user.getEmail(), user.getDisplayName(), user.getPhone(),
				user.getRoles().stream().map(Enum::name).sorted().toList());
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

	public record GenericMessage(String message) {
	}

	public record CsrfResponse(String headerName, String token) {
	}

	public record UserProfile(String email, String name, String phone, java.util.List<String> roles) {
	}

	private static ResponseEntity<GenericMessage> rateLimited() {
		return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS)
				.body(new GenericMessage("Too many requests. Please try again later."));
	}

	private static String remoteAddress(HttpServletRequest request) {
		String remoteAddress = request.getRemoteAddr();
		return remoteAddress == null ? "unknown" : remoteAddress;
	}
}
