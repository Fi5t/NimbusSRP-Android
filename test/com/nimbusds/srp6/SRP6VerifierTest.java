package com.nimbusds.srp6;


import java.math.BigInteger;


import junit.framework.*;


/**
 * Tests the SRP-6a verifier generator.
 *
 * @author <a href="http://dzhuvinov.com">Vladimir Dzhuvinov</a>
 * @version 1.3 (2011-11-08)
 */
public class SRP6VerifierTest extends TestCase {
	

	/**
	 * Creates a new test.
	 */
	public SRP6VerifierTest(String name) {
	
		super(name);
	}
	
	
	public void testConstructors() {
	
		SRP6CryptoParams config = SRP6CryptoParams.getInstance();
		
		SRP6VerifierGenerator gen = new SRP6VerifierGenerator(config);
		
		final byte[] salt = SRP6VerifierGenerator.generateRandomSalt();
		System.out.println("Salt: " + new BigInteger(salt));
		
		final String userID = "alice";
		final String password = "secret";
		
		BigInteger targetV = SRP6Routines.computeVerifier(config.N, 
		                                              config.g, 
							      SRP6Routines.computeX(config.getMessageDigestInstance(), 
							      salt, 
							      password.getBytes()));
	
		assertEquals(targetV, gen.generateVerifier(new BigInteger(salt), password));
		assertEquals(targetV, gen.generateVerifier(new BigInteger(salt), userID, password));
		assertEquals(targetV, gen.generateVerifier(salt, password.getBytes()));
		assertEquals(targetV, gen.generateVerifier(salt, userID.getBytes(), password.getBytes()));
	}
}
