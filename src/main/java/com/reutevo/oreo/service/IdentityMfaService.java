package com.reutevo.oreo.service;

import com.reutevo.oreo.entity.IdentityMfaRecoveryCode;
import com.reutevo.oreo.entity.IdentityUser;
import com.reutevo.oreo.repository.IdentityMfaRecoveryCodeRepository;
import com.reutevo.oreo.repository.IdentityUserRepository;
import com.reutevo.oreo.common.Sha256Hex;
import java.net.URLEncoder;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class IdentityMfaService {

	private static final Duration ENROLLMENT_LIFETIME = Duration.ofMinutes(10);
	private static final Duration TOTP_PERIOD = Duration.ofSeconds(30);
	private static final SecureRandom SECURE_RANDOM = new SecureRandom();
	private static final String BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

	private final IdentityUserRepository users;
	private final IdentityMfaRecoveryCodeRepository recoveryCodes;
	private final byte[] encryptionKey;

	public IdentityMfaService(
			IdentityUserRepository users,
			IdentityMfaRecoveryCodeRepository recoveryCodes,
			@Value("${identity.mfa.encryption-key}") String encodedEncryptionKey) {
		this.users = users;
		this.recoveryCodes = recoveryCodes;
		try {
			this.encryptionKey = Base64.getDecoder().decode(encodedEncryptionKey);
		}
		catch (IllegalArgumentException exception) {
			throw new IllegalArgumentException("The MFA encryption key must be Base64 encoded", exception);
		}
		if (this.encryptionKey.length != 32) {
			throw new IllegalArgumentException("The MFA encryption key must decode to 32 bytes");
		}
	}

	@Transactional
	public Enrollment beginEnrollment(String email) {
		IdentityUser user = users.findByEmailForUpdate(normalizeEmail(email)).orElseThrow();
		byte[] secretBytes = new byte[20];
		SECURE_RANDOM.nextBytes(secretBytes);
		String secret = encodeBase32(secretBytes);
		user.startMfaEnrollment(encrypt(secret), Instant.now().plus(ENROLLMENT_LIFETIME));
		String label = URLEncoder.encode("Routevo:" + user.getEmail(), StandardCharsets.UTF_8);
		String uri = "otpauth://totp/" + label + "?secret=" + secret
				+ "&issuer=Routevo&algorithm=SHA1&digits=6&period=30";
		return new Enrollment(secret, uri, user.getMfaSetupExpiresAt());
	}

	@Transactional
	public Optional<List<String>> confirmEnrollment(String email, String code) {
		IdentityUser user = users.findByEmailForUpdate(normalizeEmail(email)).orElseThrow();
		Instant now = Instant.now();
		if (user.isMfaEnabled()
				|| user.getMfaSetupExpiresAt() == null
				|| !user.getMfaSetupExpiresAt().isAfter(now)
				|| !verifyTotp(decrypt(user.getMfaSecretCiphertext()), code, now)) {
			return Optional.empty();
		}

		user.enableMfa(now);
		recoveryCodes.deleteAllByEmail(user.getEmail());
		List<String> rawCodes = new ArrayList<>();
		for (int index = 0; index < 10; index++) {
			String rawCode = recoveryCode();
			rawCodes.add(rawCode);
			recoveryCodes.save(new IdentityMfaRecoveryCode(
					user.getEmail(), Sha256Hex.digest(rawCode.replace("-", ""))));
		}
		return Optional.of(List.copyOf(rawCodes));
	}

	@Transactional
	public boolean verifyLogin(String email, String code) {
		IdentityUser user = users.findByEmailForUpdate(normalizeEmail(email)).orElse(null);
		if (user == null || !user.isMfaEnabled()) {
			return false;
		}
		Instant now = Instant.now();
		String secret = decrypt(user.getMfaSecretCiphertext());
		if (verifyTotp(secret, code, now)) {
			return true;
		}
		String normalizedCode = normalizeRecoveryCode(code);
		if (normalizedCode == null) {
			return false;
		}
		Optional<IdentityMfaRecoveryCode> recoveryCode =
				recoveryCodes.findUnusedForUpdate(user.getEmail(), Sha256Hex.digest(normalizedCode));
		recoveryCode.ifPresent(value -> value.consume(now));
		return recoveryCode.isPresent();
	}

	private String encrypt(String plaintext) {
		try {
			byte[] iv = new byte[12];
			SECURE_RANDOM.nextBytes(iv);
			Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
			cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(encryptionKey, "AES"),
					new GCMParameterSpec(128, iv));
			byte[] ciphertext = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
			byte[] combined = ByteBuffer.allocate(iv.length + ciphertext.length)
					.put(iv)
					.put(ciphertext)
					.array();
			return Base64.getUrlEncoder().withoutPadding().encodeToString(combined);
		}
		catch (GeneralSecurityException exception) {
			throw new IllegalStateException("Could not encrypt MFA secret", exception);
		}
	}

	private String decrypt(String ciphertext) {
		try {
			byte[] combined = Base64.getUrlDecoder().decode(ciphertext);
			byte[] iv = java.util.Arrays.copyOfRange(combined, 0, 12);
			byte[] encryptedSecret = java.util.Arrays.copyOfRange(combined, 12, combined.length);
			Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
			cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(encryptionKey, "AES"),
					new GCMParameterSpec(128, iv));
			return new String(cipher.doFinal(encryptedSecret), StandardCharsets.UTF_8);
		}
		catch (GeneralSecurityException | IllegalArgumentException exception) {
			throw new IllegalStateException("Could not decrypt MFA secret", exception);
		}
	}

	private static boolean verifyTotp(String secret, String code, Instant now) {
		if (code == null || !code.matches("\\d{6}")) {
			return false;
		}
		byte[] secretBytes = decodeBase32(secret);
		long currentCounter = now.getEpochSecond() / TOTP_PERIOD.toSeconds();
		for (long counter = currentCounter - 1; counter <= currentCounter + 1; counter++) {
			String expected = totp(secretBytes, counter);
			if (MessageDigest.isEqual(expected.getBytes(StandardCharsets.US_ASCII),
					code.getBytes(StandardCharsets.US_ASCII))) {
				return true;
			}
		}
		return false;
	}

	private static String totp(byte[] secret, long counter) {
		try {
			Mac hmac = Mac.getInstance("HmacSHA1");
			hmac.init(new SecretKeySpec(secret, "HmacSHA1"));
			byte[] digest = hmac.doFinal(ByteBuffer.allocate(Long.BYTES).putLong(counter).array());
			int offset = digest[digest.length - 1] & 0x0f;
			int binary = ((digest[offset] & 0x7f) << 24)
					| ((digest[offset + 1] & 0xff) << 16)
					| ((digest[offset + 2] & 0xff) << 8)
					| (digest[offset + 3] & 0xff);
			return "%06d".formatted(binary % 1_000_000);
		}
		catch (GeneralSecurityException exception) {
			throw new IllegalStateException("HmacSHA1 is required by the Java runtime", exception);
		}
	}

	private static String recoveryCode() {
		byte[] bytes = new byte[10];
		SECURE_RANDOM.nextBytes(bytes);
		String encoded = encodeBase32(bytes);
		return encoded.replaceAll("(.{4})", "$1-").replaceFirst("-$", "");
	}

	private static String normalizeRecoveryCode(String code) {
		if (code == null) {
			return null;
		}
		String normalized = code.replace("-", "").trim().toUpperCase(Locale.ROOT);
		return normalized.matches("[A-Z2-7]{16}") ? normalized : null;
	}

	private static String encodeBase32(byte[] bytes) {
		StringBuilder encoded = new StringBuilder();
		int buffer = 0;
		int bits = 0;
		for (byte value : bytes) {
			buffer = (buffer << 8) | (value & 0xff);
			bits += 8;
			while (bits >= 5) {
				encoded.append(BASE32_ALPHABET.charAt((buffer >> (bits - 5)) & 0x1f));
				bits -= 5;
			}
		}
		if (bits > 0) {
			encoded.append(BASE32_ALPHABET.charAt((buffer << (5 - bits)) & 0x1f));
		}
		return encoded.toString();
	}

	private static byte[] decodeBase32(String encoded) {
		byte[] bytes = new byte[encoded.length() * 5 / 8];
		int buffer = 0;
		int bits = 0;
		int index = 0;
		for (char character : encoded.toUpperCase(Locale.ROOT).toCharArray()) {
			int value = BASE32_ALPHABET.indexOf(character);
			if (value < 0) {
				throw new IllegalArgumentException("Invalid Base32 MFA secret");
			}
			buffer = (buffer << 5) | value;
			bits += 5;
			if (bits >= 8) {
				bytes[index++] = (byte) (buffer >> (bits - 8));
				bits -= 8;
			}
		}
		return bytes;
	}

	private static String normalizeEmail(String email) {
		return email.trim().toLowerCase(Locale.ROOT);
	}

	public record Enrollment(String secret, String otpauthUri, Instant expiresAt) {
	}
}
