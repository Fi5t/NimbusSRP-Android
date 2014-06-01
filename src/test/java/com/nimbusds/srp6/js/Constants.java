package com.nimbusds.srp6.js;

import java.math.BigInteger;
import java.security.MessageDigest;

import org.apache.commons.codec.binary.Hex;

/**
 * For testing of Javascript hashing.
 * 
 * @author Simon Massey
 */
public class Constants {
	static Hex hex = new Hex();

	public static String hashMessage = latin1(sha256("Message"));

	// raw
	public static String binaryString2f77668a9dfbf8d5 = (new BigInteger("2f77668a9dfbf8d5", 16)).toString(2);
	// padded
	public static String binaryStringPadded2f77668a9dfbf8d5 = (new BigInteger(getPadded(new BigInteger("2f77668a9dfbf8d5", 16), 128)))
			.toString(2);
	// paddedHex
	public static String hexStringPadded2f77668a9dfbf8d5 = (new BigInteger(getPadded(new BigInteger("2f77668a9dfbf8d5", 16), 128)))
			.toString(16);

	// full hashpadded
	public static String hashPaddedOf2f77668a9dfbf8d5 = hashPadded(SRP6JavascriptServerSession_N1024_SHA256.config.N,
			new BigInteger("2f77668a9dfbf8d5", 16))
			.toString(16);

	// hex hashpadded
	public static String hexHashPaddedOf2f77668a9dfbf8d5 = hashPaddedHex(new BigInteger(
			"2f77668a9dfbf8d5", 16));

	public static String latin1(byte[] bytes) {
		try {
			return new String(bytes, "Latin1");
		} catch (Exception e) {
			return null;
		}
	}

	private static byte[] sha256(String string) {
		try {
			MessageDigest digest = MessageDigest.getInstance("SHA-256");
			digest.update(string.getBytes("UTF8"));
			return digest.digest();
		} catch (Exception e) {
			throw new AssertionError(e.toString());
		}
	}

	protected static String hashPaddedHex(final BigInteger n1) {
		try {
			final MessageDigest digest = MessageDigest.getInstance("SHA-256");
			final int padLength = 128;

			byte[] n1_bytes = getPadded(n1, padLength);

			digest.update(n1_bytes);

			byte[] output = digest.digest();

			return Hex.encodeHexString(output);
		} catch (Exception e) {
			throw new AssertionError(e.toString());
		}
	}

	protected static BigInteger hashPadded(final BigInteger N, final BigInteger n1) {
		try {
			final MessageDigest digest = MessageDigest.getInstance("SHA-256");
			final int padLength = (N.bitLength() + 7) / 8;

			byte[] n1_bytes = getPadded(n1, padLength);

			digest.update(n1_bytes);

			byte[] output = digest.digest();

			return new BigInteger(1, output);
		} catch (Exception e) {
			throw new AssertionError(e.toString());
		}
	}


	protected static byte[] getPadded(final BigInteger n, final int length) {

		byte[] bs = bigIntegerToUnsignedByteArray(n);

		if (bs.length < length) {

			byte[] tmp = new byte[length];
			System.arraycopy(bs, 0, tmp, length - bs.length, bs.length);
			bs = tmp;
		}

		return bs;
	}

	protected static byte[] bigIntegerToUnsignedByteArray(final BigInteger value) {

		byte[] bytes = value.toByteArray();

		// remove leading zero if any
		if (bytes[0] == 0) {

			byte[] tmp = new byte[bytes.length - 1];

			System.arraycopy(bytes, 1, tmp, 0, tmp.length);

			return tmp;
		}

		return bytes;
	}

}
