package com.nimbusds.srp6.js;

import com.nimbusds.srp6.SRP6CryptoParams;

/**
 * Wrapper of a server session setup to interface with the Javascript client
 * session SRP6JavascriptClientSession_N1024_SHA256. BigInteger values are
 * communicated as hex strings.
 * 
 * @author Simon Massey
 */
public class SRP6JavascriptServerSession_N1024_SHA256 {
	public static SRP6CryptoParams params = SRP6CryptoParams.getInstance(1024, "SHA-256");
	
}
