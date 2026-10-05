<?php
/**
 * TOTP (RFC 6238) / HOTP (RFC 4226) implementation.
 *
 * @package   SugarCommerce\Totp
 * @copyright Copyright (c) 2026, ArrayPress Limited
 * @license   GPL-2.0-or-later
 * @since     1.0.0
 */

declare( strict_types=1 );

namespace SugarCommerce\Totp;

/**
 * Class Totp
 *
 * Time-based one-time passwords, compatible with Google Authenticator,
 * 1Password, Bitwarden, Authy, and anything else implementing RFC 6238.
 *
 * Self-contained — no dependencies, nothing to keep patched.
 *
 * Typical enrolment:
 *
 *   $totp   = new Totp();
 *   $secret = $totp->generate_secret();          // store against the user
 *   $uri    = $totp->enrolment_uri( $secret, 'dave@example.com', 'My Store' );
 *   // render $uri as a QR code
 *
 * Typical verification:
 *
 *   if ( $totp->verify( $code_from_user, $secret ) ) {
 *       // authenticated
 *   }
 *
 * Two things worth knowing before you deviate from the defaults:
 *
 *   - Leave the algorithm on SHA-1. Several major authenticator apps
 *     ignore the algorithm hint during enrolment and always use SHA-1,
 *     so anything else locks users out. See {@see Algorithm}.
 *   - Verification accepts one time step either side of now, absorbing
 *     roughly ±30 seconds of clock drift. Widening that widens the
 *     window an intercepted code stays usable in.
 *
 * @since 1.0.0
 */
final readonly class Totp {

	/**
	 * Configure the generator.
	 *
	 * @since 1.0.0
	 *
	 * @param int       $digits    Code length. 6 is universal; 8 is
	 *                             accepted by fewer apps.
	 * @param int       $period    Seconds per time step. 30 is universal.
	 * @param Algorithm $algorithm HMAC hash. Leave on SHA-1 unless you
	 *                             control both ends.
	 * @param int|null  $timestamp Fixed Unix time, for tests and
	 *                             reproducible fixtures. Null uses the
	 *                             wall clock.
	 *
	 * @throws \InvalidArgumentException When digits or period are out of range.
	 */
	public function __construct(
		private int $digits = 6,
		private int $period = 30,
		private Algorithm $algorithm = Algorithm::SHA1,
		private ?int $timestamp = null,
	) {
		if ( $digits < 6 || $digits > 10 ) {
			throw new \InvalidArgumentException( 'TOTP digits must be between 6 and 10.' );
		}

		if ( $period < 1 ) {
			throw new \InvalidArgumentException( 'TOTP period must be at least 1 second.' );
		}
	}

	/* ─── Generation ────────────────────────────────────────────────── */

	/**
	 * Generate a fresh base32 secret.
	 *
	 * Length defaults to the size recommended for the configured
	 * algorithm — 20 bytes (160 bits) for SHA-1, per RFC 4226.
	 *
	 * @since 1.0.0
	 *
	 * @param int|null $bytes Secret length in bytes. Null uses the
	 *                        algorithm's recommendation. Minimum 16.
	 *
	 * @return string Unpadded base32, safe to display and retype.
	 *
	 * @throws \InvalidArgumentException When fewer than 16 bytes are requested.
	 * @throws \Random\RandomException   When the CSPRNG is unavailable.
	 */
	public function generate_secret( ?int $bytes = null ): string {
		$bytes ??= $this->algorithm->recommended_secret_bytes();

		if ( $bytes < 16 ) {
			throw new \InvalidArgumentException( 'A TOTP secret must be at least 16 bytes (128 bits).' );
		}

		return Base32::encode( random_bytes( $bytes ), false );
	}

	/**
	 * The current code for a secret.
	 *
	 * @since 1.0.0
	 *
	 * @param string $secret Base32 secret.
	 *
	 * @return string Zero-padded code of the configured length.
	 *
	 * @throws \InvalidArgumentException When the secret is not valid base32.
	 */
	public function code( #[\SensitiveParameter] string $secret ): string {
		return $this->code_at( $secret, $this->counter() );
	}

	/**
	 * The code for a specific counter value.
	 *
	 * This is HOTP (RFC 4226). Pass a monotonic counter for HOTP proper,
	 * or `floor(time / period)` for TOTP.
	 *
	 * @since 1.0.0
	 *
	 * @param string $secret  Base32 secret.
	 * @param int    $counter Counter value.
	 *
	 * @return string Zero-padded code of the configured length.
	 *
	 * @throws \InvalidArgumentException When the secret is not valid base32.
	 */
	public function code_at( #[\SensitiveParameter] string $secret, int $counter ): string {
		$raw = Base32::decode( $secret );

		if ( false === $raw || '' === $raw ) {
			throw new \InvalidArgumentException( 'TOTP secret is not valid base32.' );
		}

		// 8-byte big-endian counter.
		$hash = hash_hmac( $this->algorithm->value, pack( 'J', $counter ), $raw, true );

		// RFC 4226 dynamic truncation: the low nibble of the final byte
		// selects a 4-byte window; the top bit is masked to dodge signed
		// integer differences between implementations.
		$offset = ord( $hash[ strlen( $hash ) - 1 ] ) & 0x0F;

		$value = ( ( ord( $hash[ $offset ] ) & 0x7F ) << 24 )
			| ( ( ord( $hash[ $offset + 1 ] ) & 0xFF ) << 16 )
			| ( ( ord( $hash[ $offset + 2 ] ) & 0xFF ) << 8 )
			| ( ord( $hash[ $offset + 3 ] ) & 0xFF );

		return str_pad(
			(string) ( $value % ( 10 ** $this->digits ) ),
			$this->digits,
			'0',
			STR_PAD_LEFT
		);
	}

	/* ─── Verification ──────────────────────────────────────────────── */

	/**
	 * Verify a user-supplied code.
	 *
	 * Comparison is constant-time. Whitespace in the submitted code is
	 * ignored, since apps display codes as `123 456`.
	 *
	 * A window of 1 accepts the previous and next time step as well as
	 * the current one, covering clock drift and a user who types slowly.
	 * Each step widens the window an intercepted code remains valid for,
	 * so keep it small.
	 *
	 * **Replay is not prevented here.** A code stays valid for its whole
	 * window, so an attacker who observes one can reuse it. Record the
	 * counter returned by {@see verify_counter()} against the user and
	 * reject anything at or below it.
	 *
	 * @since 1.0.0
	 *
	 * @param string $code   Code submitted by the user.
	 * @param string $secret Base32 secret.
	 * @param int    $window Time steps to accept either side of now.
	 *
	 * @return bool
	 */
	public function verify( #[\SensitiveParameter] string $code, #[\SensitiveParameter] string $secret, int $window = 1 ): bool {
		return null !== $this->verify_counter( $code, $secret, $window );
	}

	/**
	 * Verify a code and report which counter matched.
	 *
	 * Store the returned counter against the user and refuse any later
	 * attempt whose counter is not strictly greater. That closes the
	 * replay window {@see verify()} leaves open.
	 *
	 * @since 1.0.0
	 *
	 * @param string $code   Code submitted by the user.
	 * @param string $secret Base32 secret.
	 * @param int    $window Time steps to accept either side of now.
	 *
	 * @return int|null Matching counter, or null when nothing matched.
	 */
	public function verify_counter( #[\SensitiveParameter] string $code, #[\SensitiveParameter] string $secret, int $window = 1 ): ?int {
		$code = (string) preg_replace( '/\s+/', '', $code );

		if ( 1 !== preg_match( '/^\d{' . $this->digits . '}$/', $code ) ) {
			return null;
		}

		if ( ! Base32::is_valid( $secret ) ) {
			return null;
		}

		$window  = max( 0, $window );
		$current = $this->counter();
		$match   = null;

		// Every candidate is checked even after a hit, so verification
		// takes the same time whether the match was early, late, or
		// absent — a timing signal would otherwise leak the drift.
		for ( $offset = -$window; $offset <= $window; $offset++ ) {
			$candidate = $current + $offset;

			if ( hash_equals( $this->code_at( $secret, $candidate ), $code ) && null === $match ) {
				$match = $candidate;
			}
		}

		return $match;
	}

	/**
	 * Verify a code only if it is newer than the last one accepted.
	 *
	 * The replay guard {@see verify_counter()} leaves to the caller, in one
	 * call: a code is refused when its time step is at or below the one
	 * recorded at the last sign-in, so a code read over a shoulder — or
	 * captured by a phishing proxy and replayed seconds later — is spent
	 * the moment its owner uses it.
	 *
	 * Store the returned step as the new `$last_step`. Do that with a
	 * conditional write (`UPDATE … SET step = :new WHERE step < :new`, and
	 * check a row changed): two requests carrying the same code can both
	 * pass this check before either has saved, and only the store can say
	 * which one got there first.
	 *
	 * @since 1.1.0
	 *
	 * @param string $code      Code submitted by the user.
	 * @param string $secret    Base32 secret.
	 * @param int    $last_step Time step of the last code accepted; 0 when
	 *                          none has been.
	 * @param int    $window    Time steps to accept either side of now.
	 *
	 * @return int|null The step to record, or null for a wrong code or a
	 *                  replay.
	 */
	#[\NoDiscard( 'The step must be recorded, or the same code works again.' )]
	public function verify_after( #[\SensitiveParameter] string $code, #[\SensitiveParameter] string $secret, int $last_step, int $window = 1 ): ?int {
		$step = $this->verify_counter( $code, $secret, $window );

		return null !== $step && $step > $last_step ? $step : null;
	}

	/* ─── Enrolment ─────────────────────────────────────────────────── */

	/**
	 * Build the `otpauth://` URI for QR-code enrolment.
	 *
	 * The issuer appears both in the label and as a parameter; that
	 * duplication is what the spec asks for and what apps rely on to
	 * group entries.
	 *
	 * @since 1.0.0
	 *
	 * @param string $secret Base32 secret.
	 * @param string $account Account label — usually an email address.
	 * @param string $issuer  Service name shown in the app.
	 *
	 * @return string
	 */
	public function enrolment_uri( #[\SensitiveParameter] string $secret, string $account, string $issuer ): string {
		$label = rawurlencode( $issuer ) . ':' . rawurlencode( $account );

		$query = http_build_query(
			array(
				'secret'    => $secret,
				'issuer'    => $issuer,
				'algorithm' => $this->algorithm->uri_label(),
				'digits'    => $this->digits,
				'period'    => $this->period,
			),
			'',
			'&',
			PHP_QUERY_RFC3986
		);

		return 'otpauth://totp/' . $label . '?' . $query;
	}

	/**
	 * Seconds until the current code expires.
	 *
	 * Useful for the countdown next to a code, and for warning a user
	 * that they are about to submit one with a second left on it.
	 *
	 * @since 1.0.0
	 *
	 * @return int Between 1 and the configured period.
	 */
	public function seconds_remaining(): int {
		return $this->period - ( ( $this->timestamp ?? time() ) % $this->period );
	}

	/**
	 * The current time-step counter.
	 *
	 * @since 1.0.0
	 *
	 * @return int
	 */
	public function counter(): int {
		return intdiv( $this->timestamp ?? time(), $this->period );
	}
}
