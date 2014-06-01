package com.nimbusds.srp6.js;

import java.math.BigInteger;
import java.nio.charset.Charset;
import java.security.MessageDigest;

import com.nimbusds.srp6.Hex;
import com.nimbusds.srp6.SRP6CryptoParams;
import com.nimbusds.srp6.SRP6Routines;
import com.nimbusds.srp6.SRP6VerifierGenerator;

/**
 * We compare the javascript client with the java logic exposed using this test
 * double.
 */
public class TestDouble_N1024_SHA256 {
	public static SRP6CryptoParams config = SRP6CryptoParams.getInstance(1024, "SHA-256");
	private SRP6VerifierGenerator verifierGen = new SRP6VerifierGenerator(config);

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
		MessageDigest digest = config.getMessageDigestInstance();
		BigInteger A = fromHex(Astr);
		BigInteger B = fromHex(Bstr);
		return toHex(SRP6Routines.computeU(digest, config.N, A, B));
	}
	
	/**
	 * Pads a big integer with leading zeros up to the specified length.
	 * 
	 * @param n
	 *            The big integer to pad. Must not be {@code null}.
	 * @param length
	 *            The required length of the padded big integer as a byte array.
	 * 
	 * @return The padded big integer as a byte array.
	 */
	protected static byte[] getPadded(final BigInteger n, final int length) {

		byte[] bs = bigIntegerToUnsignedByteArray(n);

		if (bs.length < length) {

			byte[] tmp = new byte[length];
			System.arraycopy(bs, 0, tmp, length - bs.length, bs.length);
			bs = tmp;
		}

		return bs;
	}

	/**
	 * Returns the specified big integer as an unsigned byte array.
	 * 
	 * @param value
	 *            The big integer, must not be {@code null}.
	 * 
	 * @return A byte array without a leading zero if present in the signed
	 *         encoding.
	 */
	protected static byte[] bigIntegerToUnsignedByteArray(final BigInteger value) {

		byte[] bytes = value.toByteArray();

		// remove leading zero if any
		if (bytes[0] == 0) {

			byte[] tmp = new byte[bytes.length - 1];

			System.arraycopy(bytes, 1, tmp, 0, tmp.length);

			return tmp;
		}

		return bytes;
	}

	/**
	 * Hashes two padded values 'n1' and 'n2' where the total length is
	 * determined by the size of N.
	 * 
	 * <p>
	 * H(PAD(n1) | PAD(n2))
	 * 
	 * @param digest
	 *            The hash function 'H'. Must not be {@code null}.
	 * @param N
	 *            Its size determines the pad length. Must not be {@code null}.
	 * @param n1
	 *            The first value to pad and hash.
	 * @param n2
	 *            The second value to pad and hash.
	 * 
	 * @return The resulting hashed padded pair.
	 */
	protected static BigInteger hashPaddedPair(final MessageDigest digest, final BigInteger N, final BigInteger n1, final BigInteger n2) {

		final int padLength = (N.bitLength() + 7) / 8;

		// StringBuilder builder = new StringBuilder();// delete me

		byte[] n1_bytes = getPadded(n1, padLength);

		// for (int i = 0; i < n1_bytes.length; i++) { // delete me
		// builder.append(Byte.valueOf(n1_bytes[i]));
		// builder.append(',');
		// }

		// System.out.println("jvBytes: " + builder);
		// System.out.println("jvBytes.length: " + n1_bytes.length);
		// builder = new StringBuilder();

		byte[] n2_bytes = getPadded(n2, padLength);

		// for (int i = 0; i < n2_bytes.length; i++) { // delete me
		// builder.append(Byte.valueOf(n2_bytes[i]));
		// if (i < n2_bytes.length - 1) {
		// builder.append(',');
		// }
		// }

		// System.out.println("jvBytes: " + builder);
		// System.out.println("jvBytes.length: " + n2_bytes.length);

		digest.update(n1_bytes);
		digest.update(n2_bytes);

		byte[] output = digest.digest();

		// TODO delete this output

		return new BigInteger(1, output);
	}

	public String hashPaddedPair(String Astr, String Bstr) {
		MessageDigest digest = config.getMessageDigestInstance();
		BigInteger A = fromHex(Astr);
		BigInteger B = fromHex(Bstr);
		return toHex(hashPaddedPair(digest, config.N, A, B));
	}	
}
