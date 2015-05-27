/*
 * (c) LeShop SA 2015
 */
package com.nimbusds.srp6;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;

import junit.framework.TestCase;

/**
 * @author bwittwer
 */
public class SRP6SessionSerializationTest extends TestCase {

	
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

		toFile(server, "step1");

		SRP6ServerSession copy = fromFile("step1");
		
		assertEquals(SRP6ServerSession.State.STEP_1, copy.getState());
		assertEquals(s, copy.getSalt());
		
		// Step TWO

		SRP6ClientCredentials cred = null;

		try {
			cred = client.step2(config, s, B);

		} catch (SRP6Exception e) {
			fail("Client step 2 failed: " + e.getMessage());
		}

		BigInteger M2 = null;

		try {
			M2 = copy.step2(cred.A, cred.M1);
		} catch (SRP6Exception e) {
			fail("Server step 2 failed: " + e.getMessage());
		}

		assertEquals(SRP6ClientSession.State.STEP_2, client.getState());
		assertEquals(SRP6ServerSession.State.STEP_2, copy.getState());

		assertEquals(B, client.getPublicServerValue());

		assertEquals(cred.A, copy.getPublicClientValue());
		assertNotNull(copy.getServerEvidenceMessage());

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

	public void toFile(SRP6ServerSession session, String filename) {

		ObjectOutputStream oos = null;

		try {
			final FileOutputStream fichier = new FileOutputStream("target/" + filename + ".ser");
			oos = new ObjectOutputStream(fichier);

			oos.writeObject(session);

			oos.flush();

		} catch (final java.io.IOException e) {
			e.printStackTrace();
		} finally {
			try {
				if (oos != null) {
					oos.flush();
					oos.close();
				}
			} catch (final IOException ex) {
				ex.printStackTrace();
			}
		}
	}

	public SRP6ServerSession fromFile(String filename) {
		ObjectInputStream ois = null;

		try {
			final FileInputStream fichier = new FileInputStream("target/" + filename + ".ser");
			ois = new ObjectInputStream(fichier);
			final SRP6ServerSession result = (SRP6ServerSession) ois.readObject();

			return result;

		} catch (final java.io.IOException e) {
			e.printStackTrace();
			return null;
		} catch (final ClassNotFoundException e) {
			e.printStackTrace();
			return null;
		} finally {
			try {
				if (ois != null) {
					ois.close();
				}
			} catch (final IOException ex) {
				ex.printStackTrace();
			}
		}
	}

}
