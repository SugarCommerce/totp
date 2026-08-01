<?php
/**
 * Hash algorithms permitted for HOTP/TOTP.
 *
 * @package   SugarMill\Totp
 * @copyright Copyright (c) 2026, ArrayPress Limited
 * @license   GPL-2.0-or-later
 * @since     1.0.0
 */

declare( strict_types=1 );

namespace SugarMill\Totp;

/**
 * Enum Algorithm
 *
 * RFC 6238 allows SHA-1, SHA-256 and SHA-512. In practice **SHA-1 is
 * the only safe default**: Google Authenticator and several other apps
 * silently ignore the `algorithm` parameter in an enrolment URI and
 * always compute SHA-1, so enrolling with SHA-256 produces codes that
 * never match and a user who cannot log in.
 *
 * SHA-1's weakness is collision resistance, which HMAC does not depend
 * on. HMAC-SHA1 remains sound here.
 *
 * @since 1.0.0
 */
enum Algorithm: string {

	case SHA1   = 'sha1';
	case SHA256 = 'sha256';
	case SHA512 = 'sha512';

	/**
	 * Label used in an `otpauth://` URI.
	 *
	 * @since 1.0.0
	 *
	 * @return string Uppercase name, e.g. `SHA1`.
	 */
	public function uri_label(): string {
		return strtoupper( $this->value );
	}

	/**
	 * Recommended secret length in bytes.
	 *
	 * RFC 4226 requires at least 128 bits and recommends 160. The
	 * matching hash output length is the usual choice.
	 *
	 * @since 1.0.0
	 *
	 * @return int
	 */
	public function recommended_secret_bytes(): int {
		return match ( $this ) {
			self::SHA1   => 20,
			self::SHA256 => 32,
			self::SHA512 => 64,
		};
	}
}
