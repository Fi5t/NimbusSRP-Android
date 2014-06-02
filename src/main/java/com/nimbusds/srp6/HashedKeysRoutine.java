package com.nimbusds.srp6;


import java.math.BigInteger;


/**
 * Custom routine interface for computing 'u' as 'H(A | B)'.
 * 
 * <p>
 * If you don't want to employ the default {@link SRP6Routines#computeU routine}
 * for computing 'H(A | B)' message you can use this interface to define your
 * own. Remember to make sure that exactly the same routine is used by both
 * client and server session, else authentication will fail.
 * 
 * @author Simon Massey
 */
public interface HashedKeysRoutine {


	/**
	 * Computes a client evidence message 'u' as 'H(A | B)'.
	 * 
	 * @param cryptoParams
	 *            The crypto parameters for the SRP-6a protocol.
	 * @param ctx
	 *            Snapshot of the SRP-6a client session variables which may be
	 *            used in the computation of the hashed keys message.
	 * 
	 * @return The resulting 'u' as 'H(A | B)'.
	 */
	public BigInteger computeU(final SRP6CryptoParams cryptoParams, final SRP6HashedKeysContext ctx);

}
