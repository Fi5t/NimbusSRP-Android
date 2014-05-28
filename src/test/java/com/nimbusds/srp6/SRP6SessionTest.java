package com.nimbusds.srp6;


import java.math.BigInteger;

import junit.framework.TestCase;


/**
 * Tests the SRP-6a client and server session classes.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2011-11-09)
 */
public class SRP6SessionTest extends TestCase {
	

	/**
	 * Creates a new test.
	 */
	public SRP6SessionTest(String name) {
	
		super(name);
	}
	
	
	public void testAuthSuccess() {
	
		System.out.println("*** Test successful authentication ***");
		
		// username + password
		String username = "alice";
		String password = "secret";
		
		
		// crypto params
		SRP6CryptoParams config = SRP6CryptoParams.getInstance();
		
		
		// Generate verifier
		SRP6VerifierGenerator verifierGen = new SRP6VerifierGenerator(config);
		byte[] s = SRP6VerifierGenerator.generateRandomSalt();
		BigInteger v = verifierGen.generateVerifier(new BigInteger(s), username, password);
		
		System.out.println("Salt 's': " + new BigInteger(s).toString(16));
		System.out.println("Verifier 'v': " + v.toString(16));
		
		
		// Init client and server
		SRP6ClientSession client = new SRP6ClientSession();
		SRP6ServerSession server = new SRP6ServerSession(config);
		
		assertEquals(SRP6ClientSession.State.INIT, client.getState());
		assertEquals(SRP6ServerSession.State.INIT, server.getState());
		
		
		// Step ONE
		client.step1(username, password);
		BigInteger B = server.step1(username, new BigInteger(s), v);
		
		assertEquals(SRP6ClientSession.State.STEP_1, client.getState());
		assertEquals(SRP6ServerSession.State.STEP_1, server.getState());
		
		System.out.println("Client -> Server: Username: " + username);
		System.out.println("Server -> Client: B: " + B.toString(16));
		System.out.println("Server -> Client: salt: " + new BigInteger(s).toString(16));
		
		
		// Step TWO
		
		SRP6ClientCredentials cred = null;
		
		try {
			cred = client.step2(config, new BigInteger(s), B);
			
		} catch (SRP6Exception e) {
			fail("Client step 2 failed: " + e.getMessage());
		}
		
		BigInteger M2 = null;
		
		try {
			M2 = server.step2(cred.A, cred.M1);
			
		} catch (SRP6Exception e) {
			fail("Server step 2 failed: " + e.getMessage());
		}
		
		assertEquals(SRP6ClientSession.State.STEP_2, client.getState());
		assertEquals(SRP6ServerSession.State.STEP_2, server.getState());
		
		System.out.println("Client -> Server: A : " + cred.A.toString(16));
		System.out.println("Client -> Server: M1: " + cred.M1.toString(16));
		System.out.println("Server -> Client: M2: " + M2.toString(16));
		
		
		// STEP THREE
		
		try {
			client.step3(M2);
			
		} catch (SRP6Exception e) {
			fail("Client step 3 failed: " + e.getMessage());
		}
		
		assertEquals(SRP6ClientSession.State.STEP_3, client.getState());
		
		System.out.println("Auth success");
	}
}
