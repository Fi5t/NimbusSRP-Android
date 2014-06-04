package com.nimbusds.srp6;


import java.math.BigInteger;

import junit.framework.TestCase;


/**
 * Tests the BigInteger to and from hex utilities.
 *
 * @author Vladimir Dzhuvinov
 */
public class BigIntegerUtilsTest extends TestCase {


	public void testRoundTripConversion() {

		BigInteger bigInteger = new BigInteger("1234567890");

		String hex = BigIntegerUtils.toHex(bigInteger);

		assertTrue(bigInteger.equals(BigIntegerUtils.fromHex(hex)));
	}
}
