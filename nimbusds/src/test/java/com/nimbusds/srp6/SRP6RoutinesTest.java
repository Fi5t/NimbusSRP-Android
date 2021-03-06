package com.nimbusds.srp6;


import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import junit.framework.*;


/**
 * Tests the SRP-6a utility methods.
 *
 * @author Vladimir Dzhuvinov
 */
public class SRP6RoutinesTest extends TestCase {
	
	
	private MessageDigest newMessageDigest() {
	
		try {
			return MessageDigest.getInstance("SHA-1");
			
		} catch (NoSuchAlgorithmException e) {
			return null;
		}
	}

	SRP6Routines srp6Routines = new SRP6Routines();
	
	public void testComputeK() {
		
		// From http://srp.stanford.edu/demo/demo.html
		BigInteger N = new BigInteger("11144252439149533417835749556168991736939157778924947037200268358613863350040339017097790259154750906072491181606044774215413467851989724116331597513345603");
		BigInteger g = new BigInteger("2");
		
		BigInteger k = srp6Routines.computeK(newMessageDigest(), N, g);
		
		assertEquals(new BigInteger("1047744680507268333564834174388676105451778575056"), k);
	}
	
	
	public void testComputeVerifier() {
	
		// From http://srp.stanford.edu/demo/demo.html
		
		BigInteger x = new BigInteger("975978772702800114380548467521637425328799417204");
		BigInteger N = new BigInteger("11144252439149533417835749556168991736939157778924947037200268358613863350040339017097790259154750906072491181606044774215413467851989724116331597513345603");
		BigInteger g = new BigInteger("2");
		
		BigInteger v = srp6Routines.computeVerifier(N, g, x);
		
		assertEquals(new BigInteger("10836598310626950377312423287838964858494779516811208771343358321877845837932163672709518836365942491498474091391840893618271037459945669055180212495877446"), v);
	}
	
	
	public void testComputePublicClientValue() {
	
		// From http://srp.stanford.edu/demo/demo.html
		BigInteger N = new BigInteger("11144252439149533417835749556168991736939157778924947037200268358613863350040339017097790259154750906072491181606044774215413467851989724116331597513345603");
		BigInteger g = new BigInteger("2");
		BigInteger a = new BigInteger("20154524996246585496027135789045345066180872295155431171757816518311368366038");
		
		BigInteger A = srp6Routines.computePublicClientValue(N, g, a);
		
		assertEquals(new BigInteger("8637895780089258782777729314688966447633338366486605480253795600251759124373217586102292355710518187987490143639449780009742065303633343769220790787464541"), A);
	}
	
	
	public void testComputePublicServerValue() {
	
		// From http://srp.stanford.edu/demo/demo.html
		BigInteger N = new BigInteger("11144252439149533417835749556168991736939157778924947037200268358613863350040339017097790259154750906072491181606044774215413467851989724116331597513345603");
		BigInteger g = new BigInteger("2");
		BigInteger k = new BigInteger("1047744680507268333564834174388676105451778575056");
		BigInteger v = new BigInteger("7474502944304737201933065391525517979626350323656683177706520871363411502343933100270074963363249763705942958154733367887987540769816195164179972652012309");
		BigInteger b = new BigInteger("87688706387802756523846145303638946727009465033048697729929327826640915122504");

		BigInteger B = srp6Routines.computePublicServerValue(N, g, k, v, b);
		
		assertEquals(new BigInteger("9588187747518163785129397013436875944167461292974597846007987032891818936547367793638202134274048835240842528913574280725614868881714030854987066301723820"), B);
	}
	
	
	public void testComputeSessionKeyFromClientParams() {
	
		BigInteger N = new BigInteger("11144252439149533417835749556168991736939157778924947037200268358613863350040339017097790259154750906072491181606044774215413467851989724116331597513345603");
		BigInteger g = new BigInteger("2");
		BigInteger k = new BigInteger("1047744680507268333564834174388676105451778575056");
		BigInteger x = new BigInteger("359461911909460426849627852355308953854206211761");
		BigInteger u = new BigInteger("1058795856907579501448181236341287514343869634531");
		BigInteger a = new BigInteger("95736917656079566948552549320495648651648109198673221212170187788888785990505");
		BigInteger B = new BigInteger("9588187747518163785129397013436875944167461292974597846007987032891818936547367793638202134274048835240842528913574280725614868881714030854987066301723820");
	
		BigInteger S = srp6Routines.computeSessionKey(N, g, k, x, u, a, B);
		
		assertEquals(new BigInteger("1459836519616475169618381559259134652345392827028035636790323034254747322847163648105198456176319247572874754259677415649516102437458860838884341322238013"), S);
	}
	
	
	public void testComputeSessionKeyFromServerParams() {
	
		BigInteger N = new BigInteger("11144252439149533417835749556168991736939157778924947037200268358613863350040339017097790259154750906072491181606044774215413467851989724116331597513345603");
		BigInteger v = new BigInteger("7474502944304737201933065391525517979626350323656683177706520871363411502343933100270074963363249763705942958154733367887987540769816195164179972652012309");
		BigInteger u = new BigInteger("1058795856907579501448181236341287514343869634531");
		BigInteger A = new BigInteger("5851783883133110801737748616944168062144125592645124739670882600504491688868508507620920981803278916068202671958283061912270679717280194420389126894561611");
		BigInteger b = new BigInteger("87688706387802756523846145303638946727009465033048697729929327826640915122504");
	
		BigInteger S = srp6Routines.computeSessionKey(N, v, u, A, b);
		
		assertEquals(new BigInteger("1459836519616475169618381559259134652345392827028035636790323034254747322847163648105198456176319247572874754259677415649516102437458860838884341322238013"), S);
	}
	
	
	public void testAuthSuccess() {
	
		SecureRandom random = new SecureRandom();
		BigInteger N = SRP6CryptoParams.N_256;
		BigInteger g = SRP6CryptoParams.g_common;
	
		// password
		byte[] P = "secret".getBytes();
		
		// salt
		byte[] s = new byte[16];
		random.nextBytes(s);
		
		// generate verifier
		BigInteger x = srp6Routines.computeX(newMessageDigest(), s, P);
		BigInteger v = srp6Routines.computeVerifier(N, g, x);
		// System.out.println("Verifier 'v': " + v.toString(16));
		
		// generate client A
		BigInteger a = srp6Routines.generatePrivateValue(N, random);
		BigInteger A = srp6Routines.computePublicClientValue(N, g, a);
		// System.out.println("Client 'A': " + A.toString(16));
		
		// generate server B
		BigInteger b = srp6Routines.generatePrivateValue(N, random);
		BigInteger k = srp6Routines.computeK(newMessageDigest(), N, g);
		BigInteger B = srp6Routines.computePublicServerValue(N, g, k, v, b);
		// System.out.println("Server 'B': " + B.toString(16));
		
		// calcuate client S
		assertTrue("Invalid server B", srp6Routines.isValidPublicValue(N, B));
		
		BigInteger u = srp6Routines.computeU(newMessageDigest(), N, A, B);
		BigInteger S_c = srp6Routines.computeSessionKey(N, g, k, x, u, a, B);
		
		// calcuate server S
		assertTrue("Invalid client A", srp6Routines.isValidPublicValue(N, A));
		
		BigInteger S_s = srp6Routines.computeSessionKey(N, v, u, A, b);
		
		assertTrue("Auth failure: Session key mismatch", S_s.equals(S_c));
	}
	
	
	public void testAuthWithBadPassword() {
	
		// System.out.println("*** Test SRP-6a routines - bad password ***");
	
		SecureRandom random = new SecureRandom();
		BigInteger N = SRP6CryptoParams.N_256;
		BigInteger g = SRP6CryptoParams.g_common;
	
		// good + bad password
		byte[] P = "secret".getBytes();
		byte[] Pbad = "s3cr3t".getBytes();
		
		// salt
		byte[] s = new byte[16];
		random.nextBytes(s);
		
		// generate verifier
		BigInteger x = srp6Routines.computeX(newMessageDigest(), s, P);
		BigInteger xBad = srp6Routines.computeX(newMessageDigest(), s, Pbad);
		BigInteger v = srp6Routines.computeVerifier(N, g, x);
		// System.out.println("Verifier 'v': " + v.toString(16));
		
		// generate client A
		BigInteger a = srp6Routines.generatePrivateValue(N, random);
		BigInteger A = srp6Routines.computePublicClientValue(N, g, a);
		// System.out.println("Client 'A': " + A.toString(16));
		
		// generate server B
		BigInteger b = srp6Routines.generatePrivateValue(N, random);
		BigInteger k = srp6Routines.computeK(newMessageDigest(), N, g);
		BigInteger B = srp6Routines.computePublicServerValue(N, g, k, v, b);
		// System.out.println("Server 'B': " + B.toString(16));
		
		// calcuate client S
		assertTrue("Invalid server B", srp6Routines.isValidPublicValue(N, B));
		
		BigInteger u = srp6Routines.computeU(newMessageDigest(), N, A, B);
		BigInteger S_c = srp6Routines.computeSessionKey(N, g, k, xBad, u, a, B);
		
		assertTrue("Invalid client A", srp6Routines.isValidPublicValue(N, A));
		
		BigInteger S_s = srp6Routines.computeSessionKey(N, v, u, A, b);
		
		assertFalse("Unexpected auth success", S_s.equals(S_c));
	}
}
