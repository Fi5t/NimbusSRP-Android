package com.nimbusds.srp6;


import java.math.BigInteger;
import java.security.MessageDigest;

import junit.framework.*;


/**
 * Test the alternative 'x' routine interface handling.
 *
 * @author <a href="http://dzhuvinov.com">Vladimir Dzhuvinov</a>
 * @version 1.3 (2011-11-09)
 */
public class XRoutineWithUserIdentityTest extends TestCase {


	/**
	 * Creates a new test.
	 */
	public XRoutineWithUserIdentityTest(String name) {
	
		super(name);
	}
	
	
	public void test() {
	
		System.out.println("*** Test alt 'x' routine x = H(s | H(I | \":\" | P)) ***");
	
		// Use http://srp.stanford.edu/demo/demo.html as benchmark and
		// for test vectors
		BigInteger N = Hex.decodeToBigInteger("115b8b692e0e045692cf280b436735c77a5a9e8a9e7ed56c965f87db5b2a2ece3");
		BigInteger g = Hex.decodeToBigInteger("2");
		String H = "SHA-1";
		
		SRP6CryptoParams config = new SRP6CryptoParams(N, g, H);
	
		
		// Credentials
		final BigInteger salt = Hex.decodeToBigInteger("1e97da52cbdcd653f85b");
		final String userID = "alice";
		final String password = "secret";
		
		// Create verifier and set alt routine x = H(s | H(I | ":" | P))
		
		SRP6VerifierGenerator gen = new SRP6VerifierGenerator(config);
		assertNull(gen.getXRoutine());
		
		XRoutine altX = new XRoutineWithUserIdentity();
		gen.setXRoutine(altX);
		assertNotNull(gen.getXRoutine());
		
		BigInteger v = gen.generateVerifier(salt, userID, password);
		System.out.println("computed v: " + v);
		
		// From demo
		BigInteger targetV = Hex.decodeToBigInteger("100e0c40a5c281dbfb046911634f8e69d3469964863c01eb4683d8d182926da72");
		System.out.println("target   v: " + targetV);
		
		assertEquals(targetV, v);
	}
}
