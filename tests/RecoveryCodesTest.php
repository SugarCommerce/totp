<?php
/**
 * RecoveryCodes test suite.
 *
 * @package   SugarMill\Totp
 * @copyright Copyright (c) 2026, ArrayPress Limited
 * @license   GPL-2.0-or-later
 * @since     1.0.0
 */

declare( strict_types=1 );

namespace SugarMill\Totp\Tests;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SugarMill\Totp\RecoveryCodes;

final class RecoveryCodesTest extends TestCase {

	/* ─── Generation ────────────────────────────────────────────────── */

	public function test_default_set_is_ten_codes(): void {
		$this->assertCount( 10, RecoveryCodes::generate() );
	}

	public function test_default_shape_is_two_groups_of_five(): void {
		foreach ( RecoveryCodes::generate() as $code ) {
			$this->assertMatchesRegularExpression( '/^[0-9A-HJKMNP-TV-Z]{5}-[0-9A-HJKMNP-TV-Z]{5}$/', $code );
		}
	}

	public function test_shape_is_configurable(): void {
		$codes = RecoveryCodes::generate( 3, 4, 4 );

		$this->assertCount( 3, $codes );
		$this->assertMatchesRegularExpression( '/^([0-9A-Z]{4}-){3}[0-9A-Z]{4}$/', $codes[0] );
	}

	public function test_codes_are_unique_within_a_set(): void {
		$codes = RecoveryCodes::generate( 50 );

		$this->assertCount( 50, array_unique( $codes ) );
	}

	public function test_sets_differ_between_calls(): void {
		$this->assertNotSame( RecoveryCodes::generate(), RecoveryCodes::generate() );
	}

	#[DataProvider( 'ambiguous_characters' )]
	public function test_handwriting_ambiguous_letters_never_appear( string $character ): void {
		$all = implode( '', RecoveryCodes::generate( 100 ) );

		$this->assertStringNotContainsString( $character, $all );
	}

	/** @return array<string, array{0: string}> */
	public static function ambiguous_characters(): array {
		return array(
			'letter I' => array( 'I' ),
			'letter L' => array( 'L' ),
			'letter O' => array( 'O' ),
			'letter U' => array( 'U' ),
		);
	}

	public function test_degenerate_requests_are_rejected(): void {
		$this->expectException( \InvalidArgumentException::class );
		RecoveryCodes::generate( 0 );
	}

	public function test_codes_too_short_to_resist_guessing_are_rejected(): void {
		$this->expectException( \InvalidArgumentException::class );
		RecoveryCodes::generate( 10, 1, 4 );
	}

	/* ─── Normalisation ─────────────────────────────────────────────── */

	public function test_lowercase_input_is_accepted(): void {
		$this->assertSame( RecoveryCodes::normalize( 'ABCDE-FGHJK' ), RecoveryCodes::normalize( 'abcde-fghjk' ) );
	}

	public function test_hyphens_and_spaces_are_ignored(): void {
		$this->assertSame( 'ABCDEFGHJK', RecoveryCodes::normalize( ' ABCDE - FGHJK ' ) );
	}

	#[DataProvider( 'crockford_foldings' )]
	public function test_ambiguous_letters_fold_onto_digits( string $typed, string $expected ): void {
		$this->assertSame( $expected, RecoveryCodes::normalize( $typed ) );
	}

	/** @return array<string, array{0: string, 1: string}> */
	public static function crockford_foldings(): array {
		return array(
			'O for zero'      => array( 'ABCDO', 'ABCD0' ),
			'I for one'       => array( 'ABCDI', 'ABCD1' ),
			'L for one'       => array( 'ABCDL', 'ABCD1' ),
			'lowercase o'     => array( 'abcdo', 'ABCD0' ),
			'lowercase l'     => array( 'abcdl', 'ABCD1' ),
			'digits untouched' => array( 'ABCD0', 'ABCD0' ),
		);
	}

	public function test_a_code_misread_off_paper_still_verifies(): void {
		$code = '0ABCD-1EFGH';
		$hash = RecoveryCodes::hash( $code );

		// User writes O for 0 and l for 1, in lowercase, without the hyphen.
		$this->assertSame( 0, RecoveryCodes::verify( 'oabcd lefgh', array( $hash ) ) );
	}

	/* ─── Hashing ───────────────────────────────────────────────────── */

	public function test_hashes_are_not_the_plaintext(): void {
		$code = RecoveryCodes::generate( 1 )[0];

		$this->assertNotSame( $code, RecoveryCodes::hash( $code ) );
		$this->assertStringNotContainsString( str_replace( '-', '', $code ), RecoveryCodes::hash( $code ) );
	}

	public function test_the_same_code_hashes_differently_each_time(): void {
		$code = 'ABCDE-FGHJK';

		$this->assertNotSame( RecoveryCodes::hash( $code ), RecoveryCodes::hash( $code ) );
	}

	public function test_hash_all_preserves_order(): void {
		$codes  = RecoveryCodes::generate( 5 );
		$hashes = RecoveryCodes::hash_all( $codes );

		$this->assertCount( 5, $hashes );

		foreach ( $codes as $index => $code ) {
			$this->assertSame( $index, RecoveryCodes::verify( $code, $hashes ) );
		}
	}

	public function test_fresh_hashes_do_not_need_rehashing(): void {
		$this->assertFalse( RecoveryCodes::needs_rehash( RecoveryCodes::hash( 'ABCDE-FGHJK' ) ) );
	}

	/* ─── Verification ──────────────────────────────────────────────── */

	public function test_a_valid_code_returns_its_index(): void {
		$codes  = RecoveryCodes::generate( 10 );
		$hashes = RecoveryCodes::hash_all( $codes );

		$this->assertSame( 7, RecoveryCodes::verify( $codes[7], $hashes ) );
	}

	public function test_an_unknown_code_returns_null(): void {
		$hashes = RecoveryCodes::hash_all( RecoveryCodes::generate( 5 ) );

		$this->assertNull( RecoveryCodes::verify( 'ZZZZZ-ZZZZZ', $hashes ) );
	}

	public function test_an_empty_submission_returns_null(): void {
		$hashes = RecoveryCodes::hash_all( RecoveryCodes::generate( 3 ) );

		$this->assertNull( RecoveryCodes::verify( '', $hashes ) );
		$this->assertNull( RecoveryCodes::verify( '   -   ', $hashes ) );
	}

	public function test_verification_against_an_empty_set_returns_null(): void {
		$this->assertNull( RecoveryCodes::verify( 'ABCDE-FGHJK', array() ) );
	}

	public function test_malformed_stored_hashes_are_skipped(): void {
		$code   = 'ABCDE-FGHJK';
		$hashes = array( '', 'not-a-hash', RecoveryCodes::hash( $code ) );

		$this->assertSame( 2, RecoveryCodes::verify( $code, $hashes ) );
	}

	/**
	 * Single use is the caller's job — the library hands back the index
	 * so the caller can drop it. This documents that contract.
	 */
	public function test_consuming_a_code_by_index_prevents_reuse(): void {
		$codes  = RecoveryCodes::generate( 3 );
		$hashes = RecoveryCodes::hash_all( $codes );

		$index = RecoveryCodes::verify( $codes[1], $hashes );
		$this->assertSame( 1, $index );

		unset( $hashes[ $index ] );

		$this->assertNull( RecoveryCodes::verify( $codes[1], $hashes ) );
		$this->assertSame( 0, RecoveryCodes::verify( $codes[0], $hashes ) );
	}
}
