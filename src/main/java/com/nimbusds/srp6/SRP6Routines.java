package com.nimbusds.srp6;


import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.SecureRandom;


/**
 * Secure Remote Password (SRP-6a) routines for computing the various protocol 
 * variables and messages.
 *
 * <p>The routines comply with RFC 5054 (SRP for TLS), with the following 
 * exceptions:
 *
 * <ul>
 *     <li>The computation of the password key 'x' is modified to omit the user 
 *         identity 'I' in order to allow for server-side user identity renaming
 *         as well as authentication with multiple alternate identities. 
 *     <li>The evidence messages 'M1' and 'M2' are computed according to Tom 
 *         Wu's paper "SRP-6: Improvements and refinements to the Secure Remote 
 *         Password protocol", table 5, from 2002.
 * </ul>
 *
 * <p>This class contains portions of code from Bouncy Castle's SRP6 
 * implementation.
 *
 * @author Vladimir Dzhuvinov
 */
public class SRP6Routines {

	
	/**
	 * Computes the SRP-6 multiplier k = H(N | PAD(g))
	 *
	 * <p>Specification: RFC 5054.
	 *
	 * @param digest The hash function 'H'. Must not be {@code null}.
	 * @param N      The prime parameter 'N'. Must not be {@code null}.
	 * @param g      The generator parameter 'g'. Must not be {@code null}.
	 *
	 * @return The resulting multiplier 'k'.
	 */
	public static BigInteger computeK(final MessageDigest digest, 
	                                  final BigInteger N, 
	                                  final BigInteger g) {
	
		return hashPaddedPair(digest, N, N, g);
	}
	
	
	/**
	 * Generates a random salt 's'.
	 *
	 * @param numBytes The number of bytes the salt 's' must have.
	 *
	 * @return The salt 's' as a byte array.
	 */
	public static byte[] generateRandomSalt(final int numBytes) {
	
		SecureRandom random = new SecureRandom();
		
		byte[] salt = new byte[numBytes];
		
		random.nextBytes(salt);
		
		return salt;
	}
	
	
	/**
	 * Computes x = H(s | H(P))
	 *
	 * <p>Note that this method differs from the RFC 5054 recommendation 
	 * which includes the user identity 'I', i.e. x = H(s | H(I | ":" | P))
	 *
	 * @param digest   The hash function 'H'. Must not be {@code null}.
	 * @param salt     The salt 's'. Must not be {@code null}.
	 * @param password The user password 'P'. Must not be {@code null}.
	 *
	 * @return The resulting 'x' value.
	 */
	public static BigInteger computeX(final MessageDigest digest,
	                                  final byte[] salt,
	                                  final byte[] password) {         
	                                    
		byte[] output = digest.digest(password);

		digest.update(salt);
		digest.update(output);
		
		return new BigInteger(1, digest.digest());
	}
	
	
	/**
	 * Computes a verifier v = g^x (mod N)
	 *
	 * <p>Specification: RFC 5054.
	 *
	 * @param N The prime parameter 'N'. Must not be {@code null}.
	 * @param g The generator parameter 'g'. Must not be {@code null}.
	 * @param x The password key 'x', see {@link #computeX}. Must not be 
	 *          {@code null}.
	 *
	 * @return The resulting verifier 'v'.
	 */
	public static BigInteger computeVerifier(final BigInteger N,
	                                         final BigInteger g,
	                                         final BigInteger x) {
	
		return g.modPow(x, N);
	}                  
	
	
	/**
	 * Generates a random SRP-6a client or server private value ('a' or 
	 * 'b') which is 256 bits long.
	 *
	 * <p>Specification: RFC 5054.
	 *
	 * @param digest The hash function 'H'. Must not be {@code null}.
	 * @param N      The prime parameter 'N'. Must not be {@code null}.
	 * @param random Source of randomness. Must not be {@code null}.
	 *
	 * @return The resulting client or server private value ('a' or 'b').
	 */
	public static BigInteger generatePrivateValue(final MessageDigest digest, 
	                                              final BigInteger N,
	                                              final SecureRandom random) {
	 
		final int minBits = Math.min(256, N.bitLength() / 2);
		
		BigInteger min = BigInteger.ONE.shiftLeft(minBits - 1);
		BigInteger max = N.subtract(BigInteger.ONE);
		
		return createRandomBigIntegerInRange(min, max, random);               
	}
	
	
	/**
	 * Computes the public client value A = g^a (mod N)
	 *
	 * <p>Specification: RFC 5054.
	 *
	 * @param N The prime parameter 'N'. Must not be {@code null}.
	 * @param g The generator parameter 'g'. Must not be {@code null}.
	 * @param a The private client value 'a'. Must not be {@code null}.
	 *
	 * @return The public client value 'A'.
	 */
	public static BigInteger computePublicClientValue(final BigInteger N,
	                                                  final BigInteger g,
	                                                  final BigInteger a) {
	                                                    
		return g.modPow(a, N);
	}
	
	
	
	/**
	 * Computes the public server value B = k * v + g^b (mod N)
	 *
	 * <p>Specification: RFC 5054.
	 *
	 * @param N The prime parameter 'N'. Must not be {@code null}.
	 * @param g The generator parameter 'g'. Must not be {@code null}.
	 * @param k The SRP-6a multiplier 'k'. Must not be {@code null}.
	 * @param v The password verifier 'v'. Must not be {@code null}.
	 * @param b The private server value 'b'. Must not be {@code null}.
	 *
	 * @return The public server value 'B'.
	 */
	public static BigInteger computePublicServerValue(final BigInteger N,
	                                                  final BigInteger g,
	                                                  final BigInteger k,
	                                                  final BigInteger v,
	                                                  final BigInteger b) {
	
		// Original from Bouncy Castle, modified:
		// return k.multiply(v).add(g.modPow(b, N));
		
		// Below from http://srp.stanford.edu/demo/demo.html
		return g.modPow(b, N).add(v.multiply(k)).mod(N);
	}
	
	
	/**
	 * Validates an SRP6 client or server public value ('A' or 'B').
	 *
	 * <p>Specification: RFC 5054.
	 *
	 * @param N     The prime parameter 'N'. Must not be {@code null}.
	 * @param value The public value ('A' or 'B') to validate.
	 *
	 * @return {@code true} on successful validation, else {@code false}.
	 */
	public static boolean isValidPublicValue(final BigInteger N,
	                                         final BigInteger value) {
		
		// check that value % N != 0
		if (value.mod(N).equals(BigInteger.ZERO))
			return false;
		else
			return true;
	}
	
	
	/**
	 * Computes the random scrambling parameter u = H(PAD(A) | PAD(B))
	 *
	 * <p>Specification: RFC 5054.
	 *
	 * @param digest The hash function 'H'. Must not be {@code null}.
	 * @param N      The prime parameter 'N'. Must not be {@code null}.
	 * @param A      The public client value 'A'. Must not be {@code null}.
	 * @param B      The public server value 'B'. Must not be {@code null}.
	 *
	 * @return The resulting 'u' value.
	 */
	public static BigInteger computeU(final MessageDigest digest, 
	                                  final BigInteger N, 
	                                  final BigInteger A,
	                                  final BigInteger B) {
	                                   
	                                
		return hashPaddedPair(digest, N, A, B);
	}
	
	
	/**
	 * Computes the session key S = (B - k * g^x) ^ (a + u * x) (mod N)
	 * from client-side parameters.
	 * 
	 * <p>Specification: RFC 5054
	 *
	 * @param N The prime parameter 'N'. Must not be {@code null}.
	 * @param g The generator parameter 'g'. Must not be {@code null}.
	 * @param k The SRP-6a multiplier 'k'. Must not be {@code null}.
	 * @param x The 'x' value, see {@link #computeX}. Must not be 
	 *          {@code null}.
	 * @param u The random scrambling parameter 'u'. Must not be 
	 *          {@code null}.
	 * @param a The private client value 'a'. Must not be {@code null}.
	 * @param B The public server value 'B'. Must note be {@code null}.
	 *
	 * @return The resulting session key 'S'.
	 */
	public static BigInteger computeSessionKey(final BigInteger N,
	                                           final BigInteger g,
	                                           final BigInteger k,
	                                           final BigInteger x,
	                                           final BigInteger u,
	                                           final BigInteger a,
	                                           final BigInteger B) {
		
		final BigInteger exp = u.multiply(x).add(a);
		final BigInteger tmp = g.modPow(x, N).multiply(k);
		return B.subtract(tmp).modPow(exp, N);
	}
	
	
	/**
	 * Computes the session key S = (A * v^u) ^ b (mod N) from server-side
	 * parameters.
	 *
	 * <p>Specification: RFC 5054
	 *
	 * @param N The prime parameter 'N'. Must not be {@code null}.
	 * @param v The password verifier 'v'. Must not be {@code null}.
	 * @param u The random scrambling parameter 'u'. Must not be 
	 *          {@code null}.
	 * @param A The public client value 'A'. Must not be {@code null}.
	 * @param b The private server value 'b'. Must not be {@code null}.
	 *
	 * @return The resulting session key 'S'.
	 */
	public static BigInteger computeSessionKey(final BigInteger N,
	                                           final BigInteger v,
	                                           final BigInteger u,
	                                           final BigInteger A,
	                                           final BigInteger b) {
	
		return v.modPow(u, N).multiply(A).modPow(b, N);
	}
	
	
	/**
	 * Computes the client evidence message M1 = H(A | B | S)
	 *
	 * <p>Specification: Tom Wu's paper "SRP-6: Improvements and 
	 * refinements to the Secure Remote Password protocol", table 5, from 
	 * 2002.
	 *
	 * @param digest The hash function 'H'. Must not be {@code null}.
	 * @param A      The public client value 'A'. Must not be {@code null}.
	 * @param B      The public server value 'B'. Must note be {@code null}.
	 * @param S      The session key 'S'. Must not be {@code null}.
	 *
	 * @return The resulting client evidence message 'M1'.
	 */
	public static BigInteger computeClientEvidence(final MessageDigest digest,
	                                               final BigInteger A,
	                                               final BigInteger B,
	                                               final BigInteger S) {
		
		digest.update(A.toByteArray());
		digest.update(B.toByteArray());
		digest.update(S.toByteArray());

		return new BigInteger(1, digest.digest());
	}
	
	
	/**
	 * Computes the server evidence message M2 = H(A | M1 | S)
	 *
	 * <p>Specification: Tom Wu's paper "SRP-6: Improvements and 
	 * refinements to the Secure Remote Password protocol", table 5, from 
	 * 2002.
	 *
	 * @param digest The hash function 'H'. Must not be {@code null}.
	 * @param A      The public client value 'A'. Must not be {@code null}.
	 * @param M1     The client evidence message 'M1'. Must not be 
	 *               {@code null}.
	 * @param S      The session key 'S'. Must not be {@code null}.
	 *
	 * @return The resulting server evidence message 'M2'.
	 */
	protected static BigInteger computeServerEvidence(final MessageDigest digest,
	                                                  final BigInteger A,
	                                                  final BigInteger M1,
	                                                  final BigInteger S) {
	
		digest.update(A.toByteArray());
        	digest.update(M1.toByteArray());
		digest.update(S.toByteArray());
		
		return new BigInteger(1, digest.digest());
	}
	
	
	/**
	 * Hashes two padded values 'n1' and 'n2' where the total length is
	 * determined by the size of N.
	 *
	 * <p>H(PAD(n1) | PAD(n2))
	 *
	 * @param digest The hash function 'H'. Must not be {@code null}.
	 * @param N      Its size determines the pad length. Must not be 
	 *               {@code null}.
	 * @param n1     The first value to pad and hash.
	 * @param n2     The second value to pad and hash.
	 *
	 * @return The resulting hashed padded pair.
	 */
	protected static BigInteger hashPaddedPair(final MessageDigest digest,
	                                           final BigInteger N,
	                                           final BigInteger n1,
	                                           final BigInteger n2) {
	                                           
		final int padLength = (N.bitLength() + 7) / 8;
		
		byte[] n1_bytes = getPadded(n1, padLength);
		byte[] n2_bytes = getPadded(n2, padLength);
		
		digest.update(n1_bytes);
		digest.update(n2_bytes);
		
		byte[] output = digest.digest();
		
		return new BigInteger(1, output);
	}
	
	
	/**
	 * Pads a big integer with leading zeros up to the specified length.
	 *
	 * @param n      The big integer to pad. Must not be {@code null}.
	 * @param length The required length of the padded big integer as a
	 *               byte array.
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
	 * @param value The big integer, must not be {@code null}.
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
	 * Returns a random big integer in the specified range [min, max].
	 *
	 * @param min    The least value that may be generated. Must not be
	 *               {@code null}.
	 * @param max    The greatest value that may be generated. Must not be
	 *               {@code null}.
	 * @param random Source of randomness. Must not be {@code null}.
	 *
	 * @return A random big integer in the range [min, max].
	 */
	protected static BigInteger createRandomBigIntegerInRange(final BigInteger min, 
	                                                          final BigInteger max,
	                                                          final SecureRandom random) {
	
		final int cmp = min.compareTo(max);
		
		if (cmp >= 0) {
			
			if (cmp > 0)
				throw new IllegalArgumentException("'min' may not be greater than 'max'");
		
			return min;
		}

		if (min.bitLength() > max.bitLength() / 2)
			return createRandomBigIntegerInRange(BigInteger.ZERO, max.subtract(min), random).add(min);
		
		final int MAX_ITERATIONS = 1000;
		
		for (int i = 0; i < MAX_ITERATIONS; ++i) {
		
			BigInteger x = new BigInteger(max.bitLength(), random);
			
			if (x.compareTo(min) >= 0 && x.compareTo(max) <= 0)
				return x;
		}

		// fall back to a faster (restricted) method
		return new BigInteger(max.subtract(min).bitLength() - 1, random).add(min);
	}
       
       
	/**
         * Prevents instantiation.
         */
	private SRP6Routines() {

		// empty
	}
}
