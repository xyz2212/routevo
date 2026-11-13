package com.reutevo.oreo.config;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Duration;
import java.util.UUID;
import java.util.List;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.authorization.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.core.session.SessionRegistryImpl;
import org.springframework.security.web.authentication.session.ChangeSessionIdAuthenticationStrategy;
import org.springframework.security.web.authentication.session.CompositeSessionAuthenticationStrategy;
import org.springframework.security.web.authentication.session.RegisterSessionAuthenticationStrategy;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;
import org.springframework.security.web.session.HttpSessionEventPublisher;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfTokenRepository;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;

@Configuration(proxyBeanMethods = false)
public class SecurityConfiguration {

	@Bean
	PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}

	@Bean
	SecurityContextRepository securityContextRepository() {
		return new HttpSessionSecurityContextRepository();
	}

	@Bean
	SessionRegistry sessionRegistry() {
		return new SessionRegistryImpl();
	}

	@Bean
	HttpSessionEventPublisher httpSessionEventPublisher() {
		return new HttpSessionEventPublisher();
	}

	@Bean
	SessionAuthenticationStrategy sessionAuthenticationStrategy(SessionRegistry sessionRegistry) {
		return new CompositeSessionAuthenticationStrategy(List.of(
				new ChangeSessionIdAuthenticationStrategy(),
				new RegisterSessionAuthenticationStrategy(sessionRegistry)));
	}

	@Bean
	CsrfTokenRepository csrfTokenRepository(
			@Value("${identity.cookie-secure:true}") boolean secureCookies) {
		CookieCsrfTokenRepository repository = CookieCsrfTokenRepository.withHttpOnlyFalse();
		repository.setCookieCustomizer(cookie -> cookie
				.path("/")
				.secure(secureCookies)
				.sameSite("Lax"));
		return repository;
	}

	@Bean
	RegisteredClientRepository registeredClientRepository(
			@Value("${identity.client.id}") String clientId,
			@Value("${identity.client.secret}") String clientSecret,
			@Value("${identity.client.redirect-uri}") String redirectUri,
			PasswordEncoder passwordEncoder) {
		RegisteredClient client = RegisteredClient.withId(UUID.randomUUID().toString())
				.clientId(clientId)
				.clientSecret(passwordEncoder.encode(clientSecret))
				.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
				.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
				.authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
				.redirectUri(redirectUri)
				.scope(OidcScopes.OPENID)
				.scope("api.read")
				.clientSettings(ClientSettings.builder()
						.requireProofKey(true)
						.requireAuthorizationConsent(true)
						.build())
				.tokenSettings(TokenSettings.builder()
						.accessTokenTimeToLive(Duration.ofMinutes(10))
						.reuseRefreshTokens(false)
						.build())
				.build();
		return new InMemoryRegisteredClientRepository(client);
	}

	@Bean
	AuthorizationServerSettings authorizationServerSettings(
			@Value("${identity.issuer-uri}") String issuerUri) {
		return AuthorizationServerSettings.builder()
				.issuer(issuerUri)
				.build();
	}

	@Bean
	JWKSource<SecurityContext> jwkSource(
			@Value("${identity.signing-key.store}") String keyStorePath,
			@Value("${identity.signing-key.store-password}") String storePassword,
			@Value("${identity.signing-key.alias}") String keyAlias)
			throws GeneralSecurityException, IOException {
		KeyStore keyStore = KeyStore.getInstance("PKCS12");
		try (InputStream input = Files.newInputStream(Path.of(keyStorePath))) {
			keyStore.load(input, storePassword.toCharArray());
		}

		Key key = keyStore.getKey(keyAlias, storePassword.toCharArray());
		if (!(key instanceof RSAPrivateKey privateKey)) {
			throw new IllegalStateException("The configured signing-key alias must contain an RSA private key");
		}

		Certificate certificate = keyStore.getCertificate(keyAlias);
		if (certificate == null || !(certificate.getPublicKey() instanceof RSAPublicKey publicKey)) {
			throw new IllegalStateException("The configured signing-key alias must have an RSA certificate");
		}

		RSAKey rsaKey = new RSAKey.Builder(publicKey)
				.privateKey(privateKey)
				.keyID(keyAlias)
				.build();
		JWKSet jwkSet = new JWKSet(rsaKey);
		return (jwkSelector, context) -> jwkSelector.select(jwkSet);
	}

	@Bean
	@Order(0)
	SecurityFilterChain identityApiSecurityFilterChain(
			HttpSecurity http,
			SecurityContextRepository securityContextRepository,
			CsrfTokenRepository csrfTokenRepository,
			SessionRegistry sessionRegistry) throws Exception {
		http
				.securityMatcher("/api/auth/**")
				.authorizeHttpRequests(authorize -> authorize
						.requestMatchers("/api/auth/register", "/api/auth/verify-email",
								"/api/auth/resend-verification", "/api/auth/forgot-password",
								"/api/auth/reset-password", "/api/auth/login", "/api/auth/csrf",
								"/api/auth/mfa/verify", "/api/auth/accept-admin-invitation").permitAll()
						.requestMatchers("/api/auth/mfa/enrollment",
								"/api/auth/mfa/enrollment/confirm").hasAuthority("MFA_SETUP_REQUIRED")
						.requestMatchers("/api/auth/admin/**").hasRole("ADMIN")
						.requestMatchers("/api/auth/driver-application").hasRole("CUSTOMER")
						.anyRequest().authenticated())
				.securityContext(securityContext -> securityContext
						.securityContextRepository(securityContextRepository))
				.sessionManagement(session -> session.maximumSessions(-1)
						.sessionRegistry(sessionRegistry)
						.expiredSessionStrategy(event -> event.getResponse().setStatus(401)))
				.csrf(csrf -> csrf.csrfTokenRepository(csrfTokenRepository))
				.logout(logout -> logout
						.logoutUrl("/api/auth/logout")
						.logoutSuccessHandler((request, response, authentication) ->
								response.setStatus(204)))
				.exceptionHandling(exceptions -> exceptions
						.authenticationEntryPoint((request, response, exception) ->
								response.setStatus(401)));

		return http.build();
	}

	@Bean
	@Order(1)
	SecurityFilterChain apiSecurityFilterChain(HttpSecurity http) throws Exception {
		http
				.securityMatcher("/api/**", "/graphql", "/graphql/**")
				.authorizeHttpRequests(authorize -> authorize
						.anyRequest().hasAuthority("SCOPE_api.read"))
				.csrf(AbstractHttpConfigurer::disable)
				.sessionManagement(session -> session
						.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
				.oauth2ResourceServer(resourceServer -> resourceServer
						.jwt(Customizer.withDefaults()));

		return http.build();
	}

	@Bean
	@Order(-1)
	SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
		OAuth2AuthorizationServerConfigurer authorizationServerConfigurer =
				new OAuth2AuthorizationServerConfigurer();
		http
				.securityMatcher(authorizationServerConfigurer.getEndpointsMatcher())
				.with(authorizationServerConfigurer, authorizationServer ->
						authorizationServer.oidc(Customizer.withDefaults()))
				.authorizeHttpRequests(authorize -> authorize
						.anyRequest().access((authentication, context) -> {
							Authentication current = authentication.get();
							boolean mfaSetupOnly = current != null && current.getAuthorities().stream()
									.anyMatch(authority -> authority.getAuthority().equals("MFA_SETUP_REQUIRED"));
							return new AuthorizationDecision(
									current != null && current.isAuthenticated() && !mfaSetupOnly);
						}))
				.exceptionHandling(exceptions -> exceptions
						.defaultAuthenticationEntryPointFor(
								new LoginUrlAuthenticationEntryPoint("/login"),
								authorizationServerConfigurer.getEndpointsMatcher()));

		return http.build();
	}

	@Bean
	@Order(2)
	SecurityFilterChain applicationSecurityFilterChain(
			HttpSecurity http,
			SessionRegistry sessionRegistry,
			SecurityContextRepository securityContextRepository)
			throws Exception {
		http
				.authorizeHttpRequests(authorize -> authorize
						.requestMatchers("/app/**").permitAll()
						.anyRequest().authenticated())
				.sessionManagement(session -> session.maximumSessions(-1)
						.sessionRegistry(sessionRegistry))
				.formLogin(form -> form.successHandler((request, response, authentication) -> {
					boolean administrator = authentication.getAuthorities().stream()
							.anyMatch(authority -> authority.getAuthority().equals("ROLE_ADMIN"));
					if (administrator) {
						SecurityContextHolder.clearContext();
						securityContextRepository.saveContext(
								SecurityContextHolder.createEmptyContext(), request, response);
						response.sendRedirect("/app/#/login");
					}
					else {
						new SavedRequestAwareAuthenticationSuccessHandler()
								.onAuthenticationSuccess(request, response, authentication);
					}
				}));

		return http.build();
	}
}
