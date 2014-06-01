package com.nimbusds.srp6.js;

import java.math.BigInteger;

import com.nimbusds.srp6.Hex;
import com.nimbusds.srp6.SRP6CryptoParams;
import com.nimbusds.srp6.SRP6Routines;
import com.nimbusds.srp6.SRP6ServerSession;

/**
 * Wrapper of a server session setup to interface with the Javascript client
 * session SRP6JavascriptClientSession_N1024_SHA256. BigInteger values are
 * communicated as hex strings.
 * 
 * @author Simon Massey
 */
public class SRP6JavascriptServerSession_N1024_SHA256 {
	public static SRP6CryptoParams config = SRP6CryptoParams.getInstance(1024, "SHA-256");
	
	protected SRP6ServerSession session = new SRP6ServerSession(config);

	public SRP6JavascriptServerSession_N1024_SHA256() {
	}

	public String step1(String username, String salt, String v) {
		BigInteger B = session.step1(username, Hex.decodeToBigInteger(salt), Hex.decodeToBigInteger(v));
		return Hex.encode(B);
	}

	/**
	 * k is actually fixed and done with hash padding routine so best passed
	 * from the server than recomputed in every javascript client it can be
	 * cached statically.
	 */
	public static String k = Hex.encode(SRP6Routines.computeK(config.getMessageDigestInstance(), config.N, config.g));
}
