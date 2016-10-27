package com.nimbusds.srp6;


import java.math.BigInteger;

import junit.framework.*;


/**
 * Tests the SRP-6a verifier generator.
 *
 * @author Vladimir Dzhuvinov
 */
public class SRP6VerifierTest extends TestCase {
	

	public void testIssue13() throws Exception {
			SRP6CryptoParams instance = SRP6CryptoParams.getInstance();
			SRP6VerifierGenerator srp6VerifierGenerator = new SRP6VerifierGenerator(instance);
			BigInteger salt;
			byte[] saltByteArray = SRP6Routines.generateRandomSalt(16);
			saltByteArray[0] = 0;
			saltByteArray[1] |= (byte) 0x80;
			salt = new BigInteger(saltByteArray);
			BigInteger v = srp6VerifierGenerator.generateVerifier(salt, "user", "secret");
			SRP6ClientSession srp6ClientSession = new SRP6ClientSession();
			SRP6ServerSession srp6ServerSession = new SRP6ServerSession(instance);
			srp6ClientSession.step1("user", "secret");
			BigInteger b = srp6ServerSession.step1("user", salt, v);
			SRP6ClientCredentials srp6ClientCredentials = srp6ClientSession.step2(instance, salt, b);
			BigInteger m2 = srp6ServerSession.step2(srp6ClientCredentials.A, srp6ClientCredentials.M1);
			srp6ClientSession.step3(m2);
	}

	public void testConstructors() {
	
		SRP6CryptoParams config = SRP6CryptoParams.getInstance();
		
		SRP6VerifierGenerator gen = new SRP6VerifierGenerator(config);
		
		final byte[] salt = SRP6VerifierGenerator.generateRandomSalt();
		// System.out.println("Salt: " + new BigInteger(salt));
		
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


	public void testRFC5054Vector() {

		// See http://tools.ietf.org/html/rfc5054#appendix-B
		String I = "alice";
		String P = "password123";
		BigInteger salt = BigIntegerUtils.fromHex("BEB25379D1A8581EB5A727673A2441EE");

		BigInteger N = BigIntegerUtils.fromHex(
			"EEAF0AB9ADB38DD69C33F80AFA8FC5E86072618775FF3C0B9EA2314C" +
			"9C256576D674DF7496EA81D3383B4813D692C6E0E0D5D8E250B98BE4" +
			"8E495C1D6089DAD15DC7D7B46154D6B6CE8EF4AD69B15D4982559B29" +
			"7BCF1885C529F566660E57EC68EDBC3C05726CC02FD4CBF4976EAA9A" +
			"FD5138FE8376435B9FC61D2FC0EB06E3");

		BigInteger g = new BigInteger("2");

		String H = "SHA-1";

		SRP6CryptoParams params = new SRP6CryptoParams(N, g, H);
		SRP6VerifierGenerator generator = new SRP6VerifierGenerator(params);
		generator.setXRoutine(new XRoutineWithUserIdentity());

		BigInteger v = generator.generateVerifier(salt, I, P);

		BigInteger expectedV = BigIntegerUtils.fromHex(
			"7E273DE8696FFC4F4E337D05B4B375BEB0DDE1569E8FA00A9886D812" +
			"9BADA1F1822223CA1A605B530E379BA4729FDC59F105B4787E5186F5" +
			"C671085A1447B52A48CF1970B4FB6F8400BBF4CEBFBB168152E08AB5" +
			"EA53D15C1AFF87B2B9DA6E04E058AD51CC72BFC9033B564E26480D78" +
			"E955A5E29E7AB245DB2BE315E2099AFB");

		assertEquals(expectedV, v);
	}
}
