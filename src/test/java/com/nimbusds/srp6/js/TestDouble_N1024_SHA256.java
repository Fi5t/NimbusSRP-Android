package com.nimbusds.srp6.js;

import java.math.BigInteger;
import java.nio.charset.Charset;
import java.security.MessageDigest;

import com.nimbusds.srp6.BigIntegerUtils;
import com.nimbusds.srp6.SRP6CryptoParams;
import com.nimbusds.srp6.URoutineContext;
import com.nimbusds.srp6.SRP6VerifierGenerator;

/**
 * We compare the javascript client with the java logic exposed using this test
 * double.
 */
public class TestDouble_N1024_SHA256 {
	public static SRP6CryptoParams config = SRP6CryptoParams.getInstance(1024, "SHA-256");
	private SRP6VerifierGenerator verifierGen = new SRP6VerifierGenerator(config);

	private HexHashedURoutine hexStringHashedKeysRoutine = new HexHashedURoutine();

	public BigInteger fromHex(String hex) {
		return new BigInteger(hex, 16);
	}

	public String toHex(BigInteger n) {
		return n.toString(16).toUpperCase();
	}

	public String generateVerifier(String salt, String username, String password) {
		BigInteger v = verifierGen.generateVerifier(fromHex(salt), username, password);
		return BigIntegerUtils.toHex(v);
	}

	/**
	 * Browser does string concat version of x = H(salt || H(username || ":" ||
	 * password))" Specification is RFC 5054 Which we repeat here to be able to
	 * confirm that the javascript version is working within js-unit test.
	 */
	public String hashCredentials(String salt, String identity, String password) {
		MessageDigest digest = config.getMessageDigestInstance();
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
		return fromHex(hash).mod(config.N);
	}

	public String generateVerifierJavascriptAlgorithm(String salt, String identity, String password) {
		BigInteger x = generateX(salt, identity, password);
		BigInteger v = config.g.modPow(x, config.N);
		return toHex(v).toLowerCase();
	}

	public String computeU(String Astr, String Bstr) {
		BigInteger u = hexStringHashedKeysRoutine.computeU(config, new URoutineContext(fromHex(Astr), fromHex(Bstr)));
		return toHex(u);
	}
}
