package com.nimbusds.srp6;


import java.math.BigInteger;


/**
 * Hexadecimal encoding and decoding utility.
 *
 * <p>Obtained from Apache Xerces and Aduna Software code on java2s.com.
 *
 * @author Vladimir Dzhuvinov
 * @author John Kim
 * @author others
 */
public class BigIntegerUtils {

	/**
	 * Encodes the specified big integer into a hex string.
	 *
	 * @return The resulting hex encoded string or {@code null} if the
	 *         input is undefined.
	 */
	public static String toHex(final BigInteger bigint) {
	
		if (bigint == null)
			return null;
	
		return bigint.toString(16);
	}

	/**
	 * Decodes the specified hex string into a big integer.
	 *
	 * @param hex The hex encoded string to decode.
	 *
	 * @return The resulting big integer or {@code null} if decoding
	 *         failed.
	 */
	public static BigInteger fromHex(final String hex) {

		if (hex == null)
			return null;
	
		try {
			return new BigInteger(hex, 16);

		} catch (NumberFormatException e) {

			return null;
		}
	}
	
	/**
	 * Prevents instantiation.
	 */
	private BigIntegerUtils() {
	
		// do nothing
	}
}
