<?php
/**
 * Base32 test suite.
 *
 * Encoding is checked against the RFC 4648 section 10 reference vectors.
 *
 * @package   SugarCommerce\Totp
 * @copyright Copyright (c) 2026, ArrayPress Limited
 * @license   GPL-2.0-or-later
 * @since     1.0.0
 */

declare( strict_types=1 );

namespace SugarCommerce\Totp\Tests;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SugarCommerce\Totp\Base32;

final class Base32Test extends TestCase {

	/* ─── RFC 4648 reference vectors ────────────────────────────────── */

	#[DataProvider( 'rfc4648_vectors' )]
	public function test_encoding_matches_rfc_4648( string $raw, string $encoded ): void {
		$this->assertSame( $encoded, Base32::encode( $raw ) );
	}

	#[DataProvider( 'rfc4648_vectors' )]
	public function test_decoding_matches_rfc_4648( string $raw, string $encoded ): void {
		if ( '' === $raw ) {
			$this->assertFalse( Base32::decode( $encoded ) );

			return;
		}

		$this->assertSame( $raw, Base32::decode( $encoded ) );
	}

	/** @return array<string, array{0: string, 1: string}> */
	public static function rfc4648_vectors(): array {
		return array(
			'empty'  => array( '', '' ),
			'f'      => array( 'f', 'MY======' ),
			'fo'     => array( 'fo', 'MZXQ====' ),
			'foo'    => array( 'foo', 'MZXW6===' ),
			'foob'   => array( 'foob', 'MZXW6YQ=' ),
			'fooba'  => array( 'fooba', 'MZXW6YTB' ),
			'foobar' => array( 'foobar', 'MZXW6YTBOI======' ),
		);
	}

	/* ─── Round trips ───────────────────────────────────────────────── */

	#[DataProvider( 'round_trip_lengths' )]
	public function test_binary_round_trips_at_every_padding_offset( int $length ): void {
		$raw = random_bytes( $length );

		$this->assertSame( $raw, Base32::decode( Base32::encode( $raw ) ) );
	}

	/** @return array<string, array{0: int}> */
	public static function round_trip_lengths(): array {
		$out = array();

		// 1..16 covers every position in the 5-byte encoding group twice.
		for ( $i = 1; $i <= 16; $i++ ) {
			$out[ $i . ' bytes' ] = array( $i );
		}

		return $out;
	}

	public function test_unpadded_output_still_decodes(): void {
		$raw = 'foobar';

		$this->assertSame( $raw, Base32::decode( Base32::encode( $raw, false ) ) );
	}

	public function test_padding_can_be_suppressed(): void {
		$this->assertStringNotContainsString( '=', Base32::encode( 'foobar', false ) );
	}

	/* ─── Forgiving input ───────────────────────────────────────────── */

	public function test_decoding_is_case_insensitive(): void {
		$this->assertSame( Base32::decode( 'MZXW6YTB' ), Base32::decode( 'mzxw6ytb' ) );
	}

	public function test_spaces_from_authenticator_apps_are_ignored(): void {
		// This is how apps display a secret, and how users paste it back.
		$this->assertSame( Base32::decode( 'MZXW6YTBOI' ), Base32::decode( 'MZXW 6YTB OI' ) );
	}

	public function test_hyphens_are_ignored(): void {
		$this->assertSame( Base32::decode( 'MZXW6YTBOI' ), Base32::decode( 'MZXW-6YTB-OI' ) );
	}

	public function test_newlines_and_tabs_are_ignored(): void {
		$this->assertSame( Base32::decode( 'MZXW6YTB' ), Base32::decode( "MZXW\n6YTB\t" ) );
	}

	/* ─── Rejection ─────────────────────────────────────────────────── */

	#[DataProvider( 'invalid_input' )]
	public function test_invalid_input_is_rejected( string $input ): void {
		$this->assertFalse( Base32::decode( $input ) );
		$this->assertFalse( Base32::is_valid( $input ) );
	}

	/** @return array<string, array{0: string}> */
	public static function invalid_input(): array {
		return array(
			'empty'          => array( '' ),
			'only padding'   => array( '========' ),
			'only spaces'    => array( '    ' ),
			// 0, 1, 8 and 9 are excluded from the alphabet precisely
			// because they are confusable with O, I, B and g.
			'digit zero'     => array( 'MZXW0YTB' ),
			'digit one'      => array( 'MZXW1YTB' ),
			'digit eight'    => array( 'MZXW8YTB' ),
			'digit nine'     => array( 'MZXW9YTB' ),
			'punctuation'    => array( 'MZXW!YTB' ),
			'base64 padding' => array( 'MZXW+YTB' ),
			'unicode'        => array( 'MZXWé YTB' ),
		);
	}

	public function test_is_valid_accepts_a_real_secret(): void {
		$this->assertTrue( Base32::is_valid( 'JBSWY3DPEHPK3PXP' ) );
	}
}
