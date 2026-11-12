package com.reutevo.oreo;

import java.time.Duration;
import java.util.Locale;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class IdentityRateLimitService {

	private static final String UPSERT_SQL = """
			insert into identity_rate_limit_buckets (bucket_hash, window_started_at, request_count)
			values (?, current_timestamp, 1)
			on conflict (bucket_hash) do update set
				request_count = case
					when identity_rate_limit_buckets.window_started_at <=
						current_timestamp - (? * interval '1 millisecond') then 1
					else identity_rate_limit_buckets.request_count + 1
				end,
				window_started_at = case
					when identity_rate_limit_buckets.window_started_at <=
						current_timestamp - (? * interval '1 millisecond') then current_timestamp
					else identity_rate_limit_buckets.window_started_at
				end
			returning request_count
			""";

	private final JdbcTemplate jdbcTemplate;
	private final int perIpLimit;
	private final int perIdentityLimit;
	private final long windowMillis;

	public IdentityRateLimitService(
			JdbcTemplate jdbcTemplate,
			@Value("${identity.rate-limit.per-ip:30}") int perIpLimit,
			@Value("${identity.rate-limit.per-identity:10}") int perIdentityLimit,
			@Value("${identity.rate-limit.window:PT15M}") Duration window) {
		this.jdbcTemplate = jdbcTemplate;
		this.perIpLimit = perIpLimit;
		this.perIdentityLimit = perIdentityLimit;
		this.windowMillis = window.toMillis();
		if (perIpLimit < 1 || perIdentityLimit < 1 || windowMillis < 1) {
			throw new IllegalArgumentException("Identity rate limits must be positive");
		}
	}

	@Transactional
	public boolean allow(String action, String email, String remoteAddress) {
		boolean ipAllowed = increment("ip:" + action + ":" + remoteAddress, perIpLimit);
		boolean identityAllowed = email == null
				|| increment("email:" + action + ":" + normalizeEmail(email), perIdentityLimit);
		return ipAllowed && identityAllowed;
	}

	@Scheduled(cron = "0 17 4 * * *")
	public void deleteExpiredBuckets() {
		jdbcTemplate.update("""
				delete from identity_rate_limit_buckets
				where window_started_at < current_timestamp - interval '1 day'
				""");
	}

	private boolean increment(String key, int limit) {
		Integer count = jdbcTemplate.queryForObject(
				UPSERT_SQL, Integer.class, hash(key), windowMillis, windowMillis);
		return count != null && count <= limit;
	}

	private static String normalizeEmail(String email) {
		return email.trim().toLowerCase(Locale.ROOT);
	}

	private static String hash(String value) {
		return Sha256Hex.digest(value);
	}
}
