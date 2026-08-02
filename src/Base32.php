<?php
/**
 * RFC 4648 base32 encoding.
 *
 * @package   Sugar\Totp
 * @copyright Copyright (c) 2026, ArrayPress Limited
 * @license   GPL-2.0-or-later
 * @since     1.0.0
 */

declare( strict_types=1 );

namespace Sugar\Totp;

/**
 * Class Base32
 *
 * TOTP secrets are exchanged as base32 because it survives being read
 * aloud, typed on a phone keyboard, and printed on a recovery card —
 * the alphabet has no lowercase, no `0`/`1`, and no `8`/`9`.
 *
 * Decoding is deliberately forgiving: authenticator apps display secrets
 * in space-separated groups of four, and users paste them back with the
 * spaces intact, in whatever case they happen to be in.
 *
 * @since 1.0.0
 */
final readonly class Base32 {

	/**
	 * RFC 4648 base32 alphabet.
	 */
	private const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

	/**
	 * Encode raw bytes as base32.
	 *
	 * @since 1.0.0
	 *
	 * @param string $bytes Raw binary.
	 * @param bool   $pad   Emit `=` padding to a multiple of 8 characters.
	 *                      Authenticator apps accept either; padding is on
	 *                      by default for RFC conformance.
	 *
	 * @return string
	 */
	public static function encode( string $bytes, bool $pad = true ): string {
		if ( '' === $bytes ) {
			return '';
		}

		$bits = '';

		for ( $i = 0, $len = strlen( $bytes ); $i < $len; $i++ ) {
			$bits .= str_pad( decbin( ord( $bytes[ $i ] ) ), 8, '0', STR_PAD_LEFT );
		}

		$out = '';

		foreach ( str_split( $bits, 5 ) as $chunk ) {
			// The final chunk is right-padded with zero bits, per RFC 4648.
			$out .= self::ALPHABET[ bindec( str_pad( $chunk, 5, '0', STR_PAD_RIGHT ) ) ];
		}

		if ( $pad && 0 !== strlen( $out ) % 8 ) {
			$out .= str_repeat( '=', 8 - ( strlen( $out ) % 8 ) );
		}

		return $out;
	}

	/**
	 * Decode a base32 string to raw bytes.
	 *
	 * Case-insensitive. Padding, whitespace and hyphens are ignored, so
	 * a secret copied out of an authenticator app as
	 * `JBSW Y3DP EHPK 3PXP` decodes without the caller tidying it first.
	 *
	 * @since 1.0.0
	 *
	 * @param string $input Base32 text.
	 *
	 * @return string|false Raw bytes, or false when the input contains
	 *                      characters outside the alphabet.
	 */
	public static function decode( string $input ): string|false {
		$clean = strtoupper( (string) preg_replace( '/[\s\-=]/', '', $input ) );

		if ( '' === $clean ) {
			return false;
		}

		if ( 1 !== preg_match( '/^[A-Z2-7]+$/', $clean ) ) {
			return false;
		}

		$bits = '';

		for ( $i = 0, $len = strlen( $clean ); $i < $len; $i++ ) {
			$bits .= str_pad( decbin( (int) strpos( self::ALPHABET, $clean[ $i ] ) ), 5, '0', STR_PAD_LEFT );
		}

		$out = '';

		// Trailing bits that don't complete a byte are padding, not data.
		foreach ( str_split( $bits, 8 ) as $byte ) {
			if ( 8 === strlen( $byte ) ) {
				$out .= chr( bindec( $byte ) );
			}
		}

		return $out;
	}

	/**
	 * Whether a string is decodable base32.
	 *
	 * @since 1.0.0
	 *
	 * @param string $input Candidate secret.
	 *
	 * @return bool
	 */
	public static function is_valid( string $input ): bool {
		return false !== self::decode( $input );
	}
}
