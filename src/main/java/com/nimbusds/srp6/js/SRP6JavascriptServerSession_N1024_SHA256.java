package com.nimbusds.srp6.js;

import java.math.BigInteger;

import com.nimbusds.srp6.ClientEvidenceRoutine;
import com.nimbusds.srp6.URoutine;
import com.nimbusds.srp6.SRP6CryptoParams;
import com.nimbusds.srp6.SRP6Exception;
import com.nimbusds.srp6.SRP6Routines;
import com.nimbusds.srp6.SRP6ServerSession;
import com.nimbusds.srp6.ServerEvidenceRoutine;
import com.nimbusds.srp6.SRP6ServerSession.State;

import static com.nimbusds.srp6.BigIntegerUtils.fromHex;
import static com.nimbusds.srp6.BigIntegerUtils.toHex;

/**
 * Wrapper of a server session setup to interface with the Javascript client
 * session SRP6JavascriptClientSession_N1024_SHA256. BigInteger values are
 * communicated as hex strings. Hashing is done as string concat of hex numbers.
 * Does not include any session timeout logic on the assumption that can be
 * handled by web server session logic.
 * <p>
 * Specification RFC 2945.
 * 
 * @author Simon Massey
 */
public class SRP6JavascriptServerSession_N1024_SHA256 {

	public static int HASH_HEX_LENGTH = 64;

	public static SRP6CryptoParams config = SRP6CryptoParams.getInstance(1024, "SHA-256");

	protected SRP6ServerSession session = new SRP6ServerSession(config);

	protected final URoutine hexStringHashedKeysRoutine = new HexHashedURoutine();
	protected final ClientEvidenceRoutine hexStringHashedclientEvidenceRoutine = new HexHashedClientEvidenceRoutine();
	protected final ServerEvidenceRoutine hexStringHashedServerEvidenceRoutine = new HexHashedServerEvidenceRoutine();

	public SRP6JavascriptServerSession_N1024_SHA256() {
		session.setHashedKeysRoutine(hexStringHashedKeysRoutine);
		session.setClientEvidenceRoutine(hexStringHashedclientEvidenceRoutine);
		session.setServerEvidenceRoutine(hexStringHashedServerEvidenceRoutine);
	}

	/**
	 * Increments this SRP-6a authentication session to {@link State#STEP_1}.
	 * 
	 * @param userID
	 *            The identity 'I' of the authenticating user. Must not be
	 *            {@code null} or empty.
	 * @param s
	 *            The password salt 's'. Must not be {@code null}.
	 * @param v
	 *            The password verifier 'v'. Must not be {@code null}.
	 * 
	 * @return The server public value 'B' as hex encoded number.
	 * 
	 * @throws IllegalStateException
	 *             If the mehod is invoked in a state other than
	 *             {@link State#INIT}.
	 */
	public String step1(final String username, final String salt, final String v) {
		BigInteger B = session.step1(username, fromHex(salt), fromHex(v));
		return toHex(B);
	}

	/**
	 * Increments this SRP-6a authentication session to {@link State#STEP_2}.
	 * 
	 * @param A
	 *            The client public value. Must not be {@code null}.
	 * @param M1
	 *            The client evidence message. Must not be {@code null}.
	 * 
	 * @return The server evidence message 'M2' has hex encoded number with
	 *         leading zero padding to match the 256bit hash length.
	 * 
	 * @throws SRP6Exception
	 *             If the client public value 'A' is invalid or the user
	 *             credentials are invalid.
	 * 
	 * @throws IllegalStateException
	 *             If the mehod is invoked in a state other than
	 *             {@link State#STEP_1}.
	 */
	public String step2(final String A, final String M1) throws Exception {
		BigInteger M2 = session.step2(fromHex(A), fromHex(M1));
		String M2str = toHex(M2);
		M2str = HexHashedRoutines.leadingZerosPad(M2str, HASH_HEX_LENGTH);
		return M2str;
	}

	/**
	 * k is actually fixed and done with hash padding routine so passed from the
	 * server than recomputed in every javascript client.
	 */
	public static String k = toHex(SRP6Routines.computeK(config.getMessageDigestInstance(), config.N, config.g));
}
