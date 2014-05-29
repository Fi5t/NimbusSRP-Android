package com.nimbusds.srp6.js;

import java.math.BigInteger;
import java.nio.charset.Charset;
import java.security.MessageDigest;

import com.nimbusds.srp6.Hex;
import com.nimbusds.srp6.SRP6CryptoParams;
import com.nimbusds.srp6.SRP6VerifierGenerator;

/**
 * We compare the javascript client with the java logic exposed using this test
 * double.
 */
public class TestDouble_N1024_SHA256 {
	public static SRP6CryptoParams params = SRP6CryptoParams.getInstance(1024, "SHA-256");
	private SRP6VerifierGenerator verifierGen = new SRP6VerifierGenerator(params);

	public BigInteger fromHex(String hex) {
		return new BigInteger(hex, 16);
	}

	public String toHex(BigInteger n) {
		return n.toString(16).toUpperCase();
	}

	public String generateVerifier(String salt, String username, String password) {
		// System.out.println("java salt: " + toHex(fromHex(salt)));
		BigInteger v = verifierGen.generateVerifier(fromHex(salt), username, password);
		return Hex.encode(v);
	}

	/**
	 * Browser does string concat version of x = H(salt || H(username || ":" ||
	 * password))" Specification is RFC 5054 Which we repeat here to be able to
	 * confirm that the javascript version is working within js-unit test.
	 */
	public String hashCredentials(String salt, String identity, String password) {
		MessageDigest digest = params.getMessageDigestInstance();
		digest.reset();

		String concat = identity + ":" + password;

		digest.update(concat.getBytes(Charset.forName("UTF-8")));
		byte[] output = digest.digest();
		digest.reset();

		final String hash1 = toHex(new BigInteger(1, output));
		concat = (salt + hash1).toUpperCase();

		digest.update(concat.getBytes(Charset.forName("UTF-8")));
		output = digest.digest();

		return toHex(new BigInteger(1, output));
	}

	private BigInteger generateX(String salt, String identity, String password) {
		String hash = hashCredentials(salt, identity, password);
		return fromHex(hash).mod(params.N);
	}

	public String generateVerifierJavascriptAlgorithm(String salt, String identity, String password) {
		BigInteger x = generateX(salt, identity, password);
		BigInteger v = params.g.modPow(x, params.N);
		return toHex(v).toLowerCase();
	}
}
