package com.nimbusds.srp6.js;

import java.math.BigInteger;

import com.nimbusds.srp6.SRP6CryptoParams;
import static com.nimbusds.srp6.BigIntegerUtils.fromHex;
import static com.nimbusds.srp6.BigIntegerUtils.toHex;

/**
 * Wrapper of a server session setup to interface with the Javascript client
 * session SRP6JavascriptClientSession_N1024_SHA256. BigInteger values are
 * communicated as hex strings.
 * 
 * @author Simon Massey
 */
public class SRP6JavascriptServerSession_N1024_SHA256 {
	public static SRP6CryptoParams config = SRP6CryptoParams.getInstance(1024, "SHA-256");
	
	protected SRP6JavascriptServerSession session = new SRP6JavascriptServerSession(config);

	public SRP6JavascriptServerSession_N1024_SHA256() {
	}

	public String step1(final String username, final String salt, final String v) {
		BigInteger B = session.step1(username, fromHex(salt), fromHex(v));
		return toHex(B);
	}

	public String step2(final String A, final String M1) throws Exception {
		BigInteger M2 = session.step2(fromHex(A), fromHex(M1));
		return toHex(M2);
	}

	/**
	 * k is actually fixed and done with hash padding routine so best passed
	 * from the server than recomputed in every javascript client it can be
	 * cached statically.
	 */
	public static String k = toHex(SRP6JavascriptRoutines.computeK(config.getMessageDigestInstance(), config.N, config.g));
}
