package com.nimbusds.srp6;


import java.math.BigInteger;


/**
 * Immutable snapshot of SRP-6a server session variables to be used in a
 * {@link ServerEvidenceRoutine}.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2011-11-07)
 */
public class SRP6ServerEvidenceContext {


	/**
	 * The public client value 'A'.
	 */
	public final BigInteger A;
	
	
	/**
	 * The client evidence message 'M1'.
	 */
	public final BigInteger M1;
	
	
	/**
	 * The session key 'S'.
	 */
	public final BigInteger S;
	
	
	/**
	 * Creates a new immutable snapshot of SRP-6a server session variables.
	 *
	 * @param A  The public client value 'A'.
	 * @param M1 The client evidence message 'M1'.
	 * @param S  The session key 'S'.
	 */
	protected SRP6ServerEvidenceContext(final BigInteger A,
					    final BigInteger M1,
					    final BigInteger S) {
					    
		this.A = A;
		this.M1 = M1;
		this.S = S;
	}

}
