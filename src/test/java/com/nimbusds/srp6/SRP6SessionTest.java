package com.nimbusds.srp6;


import java.math.BigInteger;

import junit.framework.TestCase;


/**
 * Tests the SRP-6a client and server session classes.
 *
 * @author Vladimir Dzhuvinov
 */
public class SRP6SessionTest extends TestCase {
	
	
	public void testAuthSuccess() {
	
		// System.out.println("*** Test successful authentication ***");
		
		// username + password
		String username = "alice";
		String password = "secret";
		
		
		// crypto params
		SRP6CryptoParams config = SRP6CryptoParams.getInstance();
		
		
		// Generate verifier
		SRP6VerifierGenerator verifierGen = new SRP6VerifierGenerator(config);
		BigInteger s = new BigInteger(SRP6VerifierGenerator.generateRandomSalt());
		BigInteger v = verifierGen.generateVerifier(s, username, password);
		
		// System.out.println("Salt 's': " + s.toString(16));
		// System.out.println("Verifier 'v': " + v.toString(16));
		
		
		// Init client and server
		SRP6ClientSession client = new SRP6ClientSession();
		SRP6ServerSession server = new SRP6ServerSession(config);
		
		assertEquals(SRP6ClientSession.State.INIT, client.getState());
		assertEquals(SRP6ServerSession.State.INIT, server.getState());

		assertNull(client.getXRoutine());
		assertNull(client.getClientEvidenceRoutine());
		assertNull(client.getServerEvidenceRoutine());
		assertNull(client.getHashedKeysRoutine());
		assertEquals(0, client.getTimeout());

		assertEquals(config, server.getCryptoParams());
		assertNull(server.getClientEvidenceRoutine());
		assertNull(server.getServerEvidenceRoutine());
		assertNull(server.getHashedKeysRoutine());
		assertEquals(0, server.getTimeout());
		
		
		// Step ONE
		client.step1(username, password);
		BigInteger B = server.step1(username, s, v);
		
		assertEquals(SRP6ClientSession.State.STEP_1, client.getState());
		assertEquals(SRP6ServerSession.State.STEP_1, server.getState());

		assertEquals(username, client.getUserID());

		assertEquals(s, server.getSalt());
		
		// System.out.println("Client -> Server: Username: " + username);
		// System.out.println("Server -> Client: B: " + B.toString(16));
		// System.out.println("Server -> Client: salt: " + new
		// BigInteger(s).toString(16));
		
		// Step TWO
		
		SRP6ClientCredentials cred = null;
		
		try {
			cred = client.step2(config, s, B);
			
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

		assertEquals(B, client.getPublicServerValue());

		assertEquals(cred.A, server.getPublicClientValue());
		assertNotNull(server.getServerEvidenceMessage());
		
		// System.out.println("Client -> Server: A : " + cred.A.toString(16));
		// System.out.println("Client -> Server: M1: " + cred.M1.toString(16));
		// System.out.println("Server -> Client: M2: " + M2.toString(16));
		
		// STEP THREE
		
		try {
			client.step3(M2);
			
		} catch (SRP6Exception e) {
			fail("Client step 3 failed: " + e.getMessage());
		}
		
		assertEquals(SRP6ClientSession.State.STEP_3, client.getState());

		assertNotNull(client.getClientEvidenceMessage());
		
		// System.out.println("Auth success");
	}


	public void testSessionAttributes() {

		SRP6ClientSession client = new SRP6ClientSession();

		assertNull(client.getAttribute("name"));

		client.setAttribute("name", "alice");

		assertEquals("alice", client.getAttribute("name"));
	}
}
