package com.nimbusds.srp6;


import java.math.BigInteger;


/**
 * Immutable snapshot of the SRP-6a client session variables to be used in a
 * {@link ClientEvidenceRoutine}.
 *
 * @author Vladimir Dzhuvinov
 */
public class SRP6ClientEvidenceContext {


	/**
	 * The user identity 'I'.
	 */
	public final String userID;
	
	
	/**
	 * The salt 's' used to compute the password key 'x' (and hence the
	 * verifier 'v').
	 */
	public final BigInteger s;
	
	
	/**
	 * The public client value 'A'.
	 */
	public final BigInteger A;
	
	
	/**
	 * The public server value 'B'.
	 */
	public final BigInteger B;
	
	
	/**
	 * The session key 'S'.
	 */
	public final BigInteger S;
	
	
	/**
	 * Creates a new immutable snapshot of SRP-6a client session variables.
	 *
	 * @param userID The user identity 'I'.
	 * @param s      The salt 's' used to compute the password key 'x'.
	 * @param A      The public client value 'A'.
	 * @param B      The public server value 'B'.
	 * @param S      The session key 'S'.
	 */
	public SRP6ClientEvidenceContext(final String userID,
	                                 final BigInteger s,
					 final BigInteger A,
					 final BigInteger B,
					 final BigInteger S) {
					    
		this.userID = userID;
		this.s = s;
		this.A = A;
		this.B = B;
		this.S = S;
	}
}
