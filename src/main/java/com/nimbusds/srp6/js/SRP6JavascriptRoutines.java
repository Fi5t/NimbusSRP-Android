package com.nimbusds.srp6.js;

import static com.nimbusds.srp6.BigIntegerUtils.toHex;

import java.math.BigInteger;
import java.nio.charset.Charset;
import java.security.MessageDigest;

import com.nimbusds.srp6.SRP6Routines;

/**
 * Secure Remote Password (SRP-6a) routines for a Java sever session modified 
 * to be compatible with browser implementations by removing the dependency on 
 * the internal binary representation of java.math.BigInteger when hashing.
 *
 * <p>The routines use string space hashing of the hex encoded large numbers. 
 *
 * @author Simon Massey
 */
public class SRP6JavascriptRoutines extends SRP6Routines {
	
	public final static Charset utf8 = utf8();

	static Charset utf8() {
		return Charset.forName("UTF8");
	}

	public static BigInteger hashValues(final MessageDigest digest, final String... values) {
		final StringBuilder builder = new StringBuilder();
		for (String v : values) {
			builder.append(v);
		}
		final byte[] bytes = builder.toString().getBytes(utf8);
		digest.update(bytes, 0, bytes.length);
		return new BigInteger(1, digest.digest());
	}

	/**
	 * Computes the client evidence message M1 = H(A | B | S)
	 *
	 * <p>Specification: Tom Wu's paper "SRP-6: Improvements and 
	 * refinements to the Secure Remote Password protocol", table 5, from 
	 * 2002.
	 *
	 * @param digest The hash function 'H'. Must not be {@code null}.
	 * @param A      The public client value 'A'. Must not be {@code null}.
	 * @param B      The public server value 'B'. Must note be {@code null}.
	 * @param S      The session key 'S'. Must not be {@code null}.
	 *
	 * @return The resulting client evidence message 'M1'.
	 */
	public static BigInteger computeClientEvidence(final MessageDigest digest,
	                                               final BigInteger A,
	                                               final BigInteger B,
	                                               final BigInteger S) {
		return hashValues(digest, toHex(A), toHex(B), toHex(S));
	}
	
	
	/**
	 * Computes the server evidence message M2 = H(A | M1 | S)
	 *
	 * <p>Specification: Tom Wu's paper "SRP-6: Improvements and 
	 * refinements to the Secure Remote Password protocol", table 5, from 
	 * 2002.
	 *
	 * @param digest The hash function 'H'. Must not be {@code null}.
	 * @param A      The public client value 'A'. Must not be {@code null}.
	 * @param M1     The client evidence message 'M1'. Must not be 
	 *               {@code null}.
	 * @param S      The session key 'S'. Must not be {@code null}.
	 *
	 * @return The resulting server evidence message 'M2'.
	 */
	protected static BigInteger computeServerEvidence(final MessageDigest digest,
	                                                  final BigInteger A,
	                                                  final BigInteger M1,
	                                                  final BigInteger S) {
	
		return hashValues(digest, toHex(A), toHex(M1), toHex(S));
	}
	
	/**
	 * Computes the random scrambling parameter u = H(A | B)
	 * 
	 * @param digest
	 *            The hash function 'H'. Must not be {@code null}.
	 * @param A
	 *            The public client value 'A'. Must not be {@code null}.
	 * @param B
	 *            The public server value 'B'. Must not be {@code null}.
	 * 
	 * @return The resulting 'u' value.
	 */
	public static BigInteger computeU(final MessageDigest digest, final String Astr, final String Bstr) {
		digest.reset();
		byte[] output = digest.digest((Astr + Bstr).getBytes(utf8));
		return new BigInteger(1, output);
	}

	protected SRP6JavascriptRoutines() {
		// empty
	}
}
