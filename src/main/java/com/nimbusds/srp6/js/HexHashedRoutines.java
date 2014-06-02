package com.nimbusds.srp6.js;

import java.math.BigInteger;
import java.nio.charset.Charset;
import java.security.MessageDigest;

/**
 * Secure Remote Password (SRP-6a) hashing routine for a Java compatible with
 * browser implementations by using hashing of string concatenated hex strings.
 * 
 * <p>
 * Specification RFC 2945
 * 
 * @author Simon Massey
 */
public class HexHashedRoutines {
	
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

	private HexHashedRoutines() {
		// empty
	}

	public static String leadingZerosPad(String value, int desiredLength) {
		StringBuilder builder = new StringBuilder();
		int difference = desiredLength - value.length();
		for (int i = 0; i < difference; i++) {
			builder.append('0');
		}
		builder.append(value);
		return builder.toString();
	}
}
