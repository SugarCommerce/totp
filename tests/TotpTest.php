<?php
/**
 * TOTP test suite.
 *
 * The core of this file is the RFC 6238 Appendix B reference table.
 * Those vectors are the reason no authenticator app is needed to trust
 * this implementation: they pin the algorithm across three hash
 * functions and a time range from 1970 to 2603. A phone only proves
 * agreement at one instant.
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
use SugarMill\Totp\Algorithm;
use SugarMill\Totp\Base32;
use SugarMill\Totp\Totp;

final class TotpTest extends TestCase {

	/**
	 * RFC 6238 seeds. The document gives them as ASCII, repeated to the
	 * length each hash wants.
	 */
	private const SEED_SHA1   = '12345678901234567890';
	private const SEED_SHA256 = '12345678901234567890123456789012';
	private const SEED_SHA512 = '1234567890123456789012345678901234567890123456789012345678901234';

	private function secret_for( Algorithm $algorithm ): string {
		return Base32::encode(
			match ( $algorithm ) {
				Algorithm::SHA1   => self::SEED_SHA1,
				Algorithm::SHA256 => self::SEED_SHA256,
				Algorithm::SHA512 => self::SEED_SHA512,
			}
		);
	}

	/* ─── RFC 6238 reference vectors ────────────────────────────────── */

	#[DataProvider( 'rfc6238_vectors' )]
	public function test_matches_the_rfc_6238_reference_vectors( int $time, Algorithm $algorithm, string $expected ): void {
		$totp = new Totp( digits: 8, period: 30, algorithm: $algorithm, timestamp: $time );

		$this->assertSame( $expected, $totp->code( $this->secret_for( $algorithm ) ) );
	}

	/** @return array<string, array{0: int, 1: Algorithm, 2: string}> */
	public static function rfc6238_vectors(): array {
		$table = array(
			// time         sha1        sha256      sha512
			array( 59,          '94287082', '46119246', '90693936' ),
			array( 1111111109,  '07081804', '68084774', '25091201' ),
			array( 1111111111,  '14050471', '67062674', '99943326' ),
			array( 1234567890,  '89005924', '91819424', '93441116' ),
			array( 2000000000,  '69279037', '90698825', '38618901' ),
			array( 20000000000, '65353130', '77737706', '47863826' ),
		);

		$out = array();

		foreach ( $table as [ $time, $sha1, $sha256, $sha512 ] ) {
			$out[ "t={$time} sha1" ]   = array( $time, Algorithm::SHA1, $sha1 );
			$out[ "t={$time} sha256" ] = array( $time, Algorithm::SHA256, $sha256 );
			$out[ "t={$time} sha512" ] = array( $time, Algorithm::SHA512, $sha512 );
		}

		return $out;
	}

	public function test_six_digit_codes_are_the_last_six_of_the_eight_digit_vector(): void {
		$secret = $this->secret_for( Algorithm::SHA1 );

		$this->assertSame(
			'287082',
			( new Totp( timestamp: 59 ) )->code( $secret )
		);
	}

	/* ─── Counter arithmetic ────────────────────────────────────────── */

	public function test_the_counter_is_time_divided_by_period(): void {
		$this->assertSame( 1, ( new Totp( timestamp: 59 ) )->counter() );
		$this->assertSame( 2, ( new Totp( timestamp: 60 ) )->counter() );
		$this->assertSame( 0, ( new Totp( timestamp: 29 ) )->counter() );
	}

	public function test_the_code_is_stable_across_a_single_time_step(): void {
		$secret = $this->secret_for( Algorithm::SHA1 );

		$this->assertSame(
			( new Totp( timestamp: 30 ) )->code( $secret ),
			( new Totp( timestamp: 59 ) )->code( $secret )
		);
	}

	public function test_the_code_changes_at_the_step_boundary(): void {
		$secret = $this->secret_for( Algorithm::SHA1 );

		$this->assertNotSame(
			( new Totp( timestamp: 59 ) )->code( $secret ),
			( new Totp( timestamp: 60 ) )->code( $secret )
		);
	}

	public function test_seconds_remaining_counts_down_within_the_step(): void {
		$this->assertSame( 30, ( new Totp( timestamp: 60 ) )->seconds_remaining() );
		$this->assertSame( 1, ( new Totp( timestamp: 59 ) )->seconds_remaining() );
		$this->assertSame( 15, ( new Totp( timestamp: 45 ) )->seconds_remaining() );
	}

	public function test_a_custom_period_is_honoured(): void {
		$this->assertSame( 1, ( new Totp( period: 60, timestamp: 90 ) )->counter() );
	}

	/* ─── Verification ──────────────────────────────────────────────── */

	public function test_the_current_code_verifies(): void {
		$secret = $this->secret_for( Algorithm::SHA1 );
		$totp   = new Totp( timestamp: 1234567890 );

		$this->assertTrue( $totp->verify( $totp->code( $secret ), $secret ) );
	}

	public function test_a_wrong_code_is_rejected(): void {
		$this->assertFalse( ( new Totp( timestamp: 1234567890 ) )->verify( '000000', $this->secret_for( Algorithm::SHA1 ) ) );
	}

	public function test_whitespace_in_the_submitted_code_is_ignored(): void {
		$secret = $this->secret_for( Algorithm::SHA1 );
		$totp   = new Totp( timestamp: 1234567890 );
		$code   = $totp->code( $secret );

		$this->assertTrue( $totp->verify( substr( $code, 0, 3 ) . ' ' . substr( $code, 3 ), $secret ) );
	}

	public function test_the_previous_time_step_is_accepted_within_the_window(): void {
		$secret   = $this->secret_for( Algorithm::SHA1 );
		$previous = ( new Totp( timestamp: 1234567890 - 30 ) )->code( $secret );

		$this->assertTrue( ( new Totp( timestamp: 1234567890 ) )->verify( $previous, $secret, 1 ) );
	}

	public function test_the_next_time_step_is_accepted_within_the_window(): void {
		$secret = $this->secret_for( Algorithm::SHA1 );
		$next   = ( new Totp( timestamp: 1234567890 + 30 ) )->code( $secret );

		$this->assertTrue( ( new Totp( timestamp: 1234567890 ) )->verify( $next, $secret, 1 ) );
	}

	public function test_a_zero_window_accepts_only_the_current_step(): void {
		$secret   = $this->secret_for( Algorithm::SHA1 );
		$previous = ( new Totp( timestamp: 1234567890 - 30 ) )->code( $secret );

		$this->assertFalse( ( new Totp( timestamp: 1234567890 ) )->verify( $previous, $secret, 0 ) );
	}

	public function test_a_code_beyond_the_window_is_rejected(): void {
		$secret = $this->secret_for( Algorithm::SHA1 );
		$far    = ( new Totp( timestamp: 1234567890 + 300 ) )->code( $secret );

		$this->assertFalse( ( new Totp( timestamp: 1234567890 ) )->verify( $far, $secret, 1 ) );
	}

	public function test_verify_counter_reports_which_step_matched(): void {
		$secret = $this->secret_for( Algorithm::SHA1 );
		$totp   = new Totp( timestamp: 1234567890 );
		$now    = $totp->counter();

		$this->assertSame( $now, $totp->verify_counter( $totp->code( $secret ), $secret ) );
		$this->assertSame(
			$now - 1,
			$totp->verify_counter( ( new Totp( timestamp: 1234567890 - 30 ) )->code( $secret ), $secret )
		);
	}

	public function test_verify_counter_returns_null_on_failure(): void {
		$this->assertNull( ( new Totp( timestamp: 1234567890 ) )->verify_counter( '000000', $this->secret_for( Algorithm::SHA1 ) ) );
	}

	#[DataProvider( 'malformed_codes' )]
	public function test_malformed_codes_are_rejected( string $code ): void {
		$this->assertFalse( ( new Totp( timestamp: 1234567890 ) )->verify( $code, $this->secret_for( Algorithm::SHA1 ) ) );
	}

	/** @return array<string, array{0: string}> */
	public static function malformed_codes(): array {
		return array(
			'empty'      => array( '' ),
			'too short'  => array( '12345' ),
			'too long'   => array( '1234567' ),
			'letters'    => array( 'abcdef' ),
			'mixed'      => array( '12a456' ),
			'negative'   => array( '-12345' ),
			'hex'        => array( '0x1234' ),
		);
	}

	public function test_an_invalid_secret_fails_verification_rather_than_throwing(): void {
		$this->assertFalse( ( new Totp() )->verify( '123456', 'not!valid!base32' ) );
	}

	public function test_a_negative_window_is_treated_as_zero(): void {
		$secret = $this->secret_for( Algorithm::SHA1 );
		$totp   = new Totp( timestamp: 1234567890 );

		$this->assertTrue( $totp->verify( $totp->code( $secret ), $secret, -5 ) );
	}

	/* ─── Secret generation ─────────────────────────────────────────── */

	public function test_generated_secrets_are_valid_base32(): void {
		$this->assertTrue( Base32::is_valid( ( new Totp() )->generate_secret() ) );
	}

	public function test_generated_secrets_default_to_160_bits(): void {
		$this->assertSame( 20, strlen( (string) Base32::decode( ( new Totp() )->generate_secret() ) ) );
	}

	public function test_secret_length_follows_the_algorithm(): void {
		$this->assertSame(
			32,
			strlen( (string) Base32::decode( ( new Totp( algorithm: Algorithm::SHA256 ) )->generate_secret() ) )
		);
	}

	public function test_generated_secrets_are_unpadded(): void {
		$this->assertStringNotContainsString( '=', ( new Totp() )->generate_secret() );
	}

	public function test_generated_secrets_are_unique(): void {
		$totp    = new Totp();
		$secrets = array();

		for ( $i = 0; $i < 50; $i++ ) {
			$secrets[] = $totp->generate_secret();
		}

		$this->assertCount( 50, array_unique( $secrets ) );
	}

	public function test_a_generated_secret_round_trips_through_code_generation(): void {
		$totp   = new Totp( timestamp: 1234567890 );
		$secret = $totp->generate_secret();

		$this->assertMatchesRegularExpression( '/^\d{6}$/', $totp->code( $secret ) );
	}

	public function test_secrets_below_128_bits_are_refused(): void {
		$this->expectException( \InvalidArgumentException::class );
		( new Totp() )->generate_secret( 8 );
	}

	/* ─── Configuration guards ──────────────────────────────────────── */

	#[DataProvider( 'bad_digits' )]
	public function test_unsupported_digit_counts_are_rejected( int $digits ): void {
		$this->expectException( \InvalidArgumentException::class );
		new Totp( digits: $digits );
	}

	/** @return array<string, array{0: int}> */
	public static function bad_digits(): array {
		return array(
			'zero'     => array( 0 ),
			'too few'  => array( 5 ),
			'too many' => array( 11 ),
			'negative' => array( -6 ),
		);
	}

	public function test_a_non_positive_period_is_rejected(): void {
		$this->expectException( \InvalidArgumentException::class );
		new Totp( period: 0 );
	}

	public function test_an_invalid_secret_throws_when_generating(): void {
		$this->expectException( \InvalidArgumentException::class );
		( new Totp() )->code( 'not!base32' );
	}

	/* ─── Enrolment URI ─────────────────────────────────────────────── */

	public function test_enrolment_uri_shape(): void {
		$uri = ( new Totp() )->enrolment_uri( 'JBSWY3DPEHPK3PXP', 'dave@example.com', 'My Store' );

		$this->assertStringStartsWith( 'otpauth://totp/My%20Store:dave%40example.com?', $uri );
		$this->assertStringContainsString( 'secret=JBSWY3DPEHPK3PXP', $uri );
		$this->assertStringContainsString( 'issuer=My%20Store', $uri );
		$this->assertStringContainsString( 'algorithm=SHA1', $uri );
		$this->assertStringContainsString( 'digits=6', $uri );
		$this->assertStringContainsString( 'period=30', $uri );
	}

	public function test_enrolment_uri_reflects_configuration(): void {
		$uri = ( new Totp( digits: 8, period: 60, algorithm: Algorithm::SHA256 ) )
			->enrolment_uri( 'JBSWY3DPEHPK3PXP', 'a@b.com', 'Acme' );

		$this->assertStringContainsString( 'algorithm=SHA256', $uri );
		$this->assertStringContainsString( 'digits=8', $uri );
		$this->assertStringContainsString( 'period=60', $uri );
	}

	public function test_enrolment_uri_escapes_separators_in_labels(): void {
		$uri = ( new Totp() )->enrolment_uri( 'JBSWY3DPEHPK3PXP', 'a:b@example.com', 'Store: Main' );

		// The ':' between issuer and account must be the only unescaped one
		// after the scheme, or apps split the label incorrectly.
		$path = substr( $uri, strlen( 'otpauth://totp/' ), strpos( $uri, '?' ) - strlen( 'otpauth://totp/' ) );
		$this->assertSame( 1, substr_count( $path, ':' ) );
	}

	/* ─── Algorithm metadata ────────────────────────────────────────── */

	public function test_algorithm_uri_labels(): void {
		$this->assertSame( 'SHA1', Algorithm::SHA1->uri_label() );
		$this->assertSame( 'SHA256', Algorithm::SHA256->uri_label() );
		$this->assertSame( 'SHA512', Algorithm::SHA512->uri_label() );
	}

	public function test_recommended_secret_sizes_match_hash_output(): void {
		$this->assertSame( 20, Algorithm::SHA1->recommended_secret_bytes() );
		$this->assertSame( 32, Algorithm::SHA256->recommended_secret_bytes() );
		$this->assertSame( 64, Algorithm::SHA512->recommended_secret_bytes() );
	}
}
