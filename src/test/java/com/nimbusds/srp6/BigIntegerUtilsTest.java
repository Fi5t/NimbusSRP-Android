package com.nimbusds.srp6;


import java.math.BigInteger;

import junit.framework.TestCase;


/**
 * Tests the BigInteger to and from hex utilities.
 *
 * @author Vladimir Dzhuvinov
 */
public class BigIntegerUtilsTest extends TestCase {


	public void testHexRoundTrip1() {

		BigInteger bigInteger = new BigInteger("1234567890");

		String hex = BigIntegerUtils.toHex(bigInteger);

		assertTrue(bigInteger.equals(BigIntegerUtils.fromHex(hex)));
	}


	public void testHexRoundTrip2() {

		String hex = "beb25379d1a8581eb5a727673a2441ee";

		BigInteger bigInteger = BigIntegerUtils.fromHex(hex);

		assertTrue(hex.equals(BigIntegerUtils.toHex(bigInteger)));
	}


	public void testHexCaseInsensitive() {

		String hex1 = "beb25379d1a8581eb5a727673a2441ee";
		String hex2 = "BEB25379D1A8581EB5A727673A2441EE";

		assertEquals(BigIntegerUtils.fromHex(hex1), BigIntegerUtils.fromHex(hex2));
	}

	public void testBinaryRoundTrip1() {
		String hex = "beb25379d1a8581eb5a727673a2441ee";

		BigInteger bigInteger = BigIntegerUtils.fromHex(hex);

		byte[] bytes = BigIntegerUtils.bigIntegerToBytes(bigInteger);

		BigInteger from = BigIntegerUtils.bigIntegerFromBytes(bytes);

		assertEquals(bigInteger ,from);
	}

}
