package com.nimbusds.srp6;


import java.math.BigInteger;

import junit.framework.TestCase;


/**
 * Tests the SRP6 crypto params.
 */
public class SRP6CryptoParamsTest extends TestCase {


	public void testPrecomputedPrimes() {

		assertTrue(SRP6CryptoParams.N_256.isProbablePrime(15));
		assertTrue(SRP6CryptoParams.N_512.isProbablePrime(15));
		assertTrue(SRP6CryptoParams.N_768.isProbablePrime(15));
		assertTrue(SRP6CryptoParams.N_1024.isProbablePrime(15));
		assertTrue(SRP6CryptoParams.N_2048.isProbablePrime(15));
	}


	public void testIllegalGeneratorArg() {

		try {
			new SRP6CryptoParams(SRP6CryptoParams.N_256, null, "SHA-1");
			fail();
		} catch (IllegalArgumentException e) {
			assertEquals("The generator parameter 'g' must not be null", e.getMessage());
		}

		try {
			new SRP6CryptoParams(SRP6CryptoParams.N_256, BigInteger.ONE, "SHA-1");
			fail();
		} catch (IllegalArgumentException e) {
			assertEquals("The generator parameter 'g' must not be 1", e.getMessage());
		}

		try {
			new SRP6CryptoParams(SRP6CryptoParams.N_256, SRP6CryptoParams.N_256.subtract(BigInteger.ONE), "SHA-1");
			fail();
		} catch (IllegalArgumentException e) {
			assertEquals("The generator parameter 'g' must not equal N - 1", e.getMessage());
		}

		try {
			new SRP6CryptoParams(SRP6CryptoParams.N_256, BigInteger.ZERO, "SHA-1");
			fail();
		} catch (IllegalArgumentException e) {
			assertEquals("The generator parameter 'g' must not be 0", e.getMessage());
		}
	}
}
