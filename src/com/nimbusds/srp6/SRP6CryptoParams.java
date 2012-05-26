package com.nimbusds.srp6;


import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;


/**
 * The crypto parameters for the SRP-6a protocol. These must be agreed between
 * client and server before authentication and consist of a large safe prime 
 * 'N', a corresponding generator 'g' and a hash function algorithm 'H'.
 *
 * <p>The practical approach is to have the server manage these and make them 
 * available to clients on request. This way, the client does not need to 
 * anticipate or otherwise keep track of which parameters are used for which 
 * users or servers; it only needs to verify their validity, which can be done 
 * mathematically or by simple table lookup.
 *
 * <p>For convenience this class includes a set of precomputed parameters,
 * obtained from the SRP-6a demo at http://srp.stanford.edu/demo/demo.html.
 *
 * @author <a href="http://dzhuvinov.com">Vladimir Dzhuvinov</a>
 * @version 1.3 (2011-10-29)
 */
public class SRP6CryptoParams {

	
	// Pre-computed primes 'N' for a set of bitsizes

	
	/**
	 * Precomputed safe 256-bit prime 'N', as decimal.
	 */
	public static final BigInteger N_256 = new BigInteger("125617018995153554710546479714086468244499594888726646874671447258204721048803");
	
	
	/**
	 * Precomputed safe 512-bit prime 'N', as decimal.
	 */
	public static final BigInteger N_512 = new BigInteger("11144252439149533417835749556168991736939157778924947037200268358613863350040339017097790259154750906072491181606044774215413467851989724116331597513345603");
	 
	 
	/**
	 * Precomputed safe 768-bit prime 'N', as decimal.
	 */
	public static final BigInteger N_768 = new BigInteger("1087179135105457859072065649059069760280540086975817629066444682366896187793570736574549981488868217843627094867924800342887096064844227836735667168319981288765377499806385489913341488724152562880918438701129530606139552645689583147");
	 
	 
	/**
	 * Precomputed safe 1024-bit prime 'N', as decimal.
	 */
	public static final BigInteger N_1024 = new BigInteger("167609434410335061345139523764350090260135525329813904557420930309800865859473551531551523800013916573891864789934747039010546328480848979516637673776605610374669426214776197828492691384519453218253702788022233205683635831626913357154941914129985489522629902540768368409482248290641036967659389658897350067939");
	
	
	/**
	 * Generator 'g' parameter for {@link #N_256}, {@link #N_512}, 
	 * {@link #N_768} and {@link #N_1024}, as decimal.
	 */
	public static final BigInteger g_common = BigInteger.valueOf(2);
	
	
	/**
	 * The safe prime 'N'.
	 */
	public final BigInteger N;
	
	
	/**
	 * The corresponding generator 'g'.
	 */
	public final BigInteger g;
	
	
	/**
	 * The hash algorithm 'H'.
	 */
	public final String H;
	
	
	/**
	 * Returns an SRP-6a crypto parameters instance with precomputed 'N' and
	 * 'g' values and the specified hash algorithm 'H'.
	 *
	 * @param bitsize The preferred prime number bitsize. Must exist as a 
	 *                precomputed constant.
	 * @param H       The preferred hash algorithm. Must be supported by the 
	 *                default security provider of the underlying Java 
	 *                runtime.
	 *
	 * @return The matching SRP-6a crypto parameters instance, or
	 *         {@code null} if no matching constants or hash algorithm
	 *         provider could be found.
	 */
	public static SRP6CryptoParams getInstance(final int bitsize, final String H) {
	
		if (H == null || H.isEmpty())
			throw new IllegalArgumentException("Undefined hash algorithm 'H'");
			
		if (bitsize == 256)
			return new SRP6CryptoParams(N_256, g_common, H);
		
		else if (bitsize == 512)
			return new SRP6CryptoParams(N_512, g_common, H);
			
		else if (bitsize == 768)
			return new SRP6CryptoParams(N_768, g_common, H);
			
		else if (bitsize == 1024)
			return new SRP6CryptoParams(N_1024, g_common, H);
		
		else
			return null;
	}
	
	
	/**
	 * Returns an SRP-6a crypto parameters instance with precomputed 
	 * 512-bit prime 'N', matching 'g' value and "SHA-1" hash algorithm.
	 *
	 * @return SRP-6a crypto parameters instance with 512-bit prime 'N',
	 *         matching 'g' value and "SHA-1" hash algorithm.
	 */
	public static SRP6CryptoParams getInstance() {
	
		return getInstance(512, "SHA-1");
	}
	
	
	/**
	 * Checks if the specified hash algorithm 'H' is supported by the 
	 * default security provider of the underlying Java runtime.
	 *
	 * @param H The hash algorithm to check, e.g. "SHA-1".
	 *
	 * @return {@code true} if the hash algorightm is supported, else
	 *         {@code false}.
	 */
	public static boolean isSupportedHashAlgorithm(final String H) {
	
		try {
			MessageDigest.getInstance(H);
			
			return true; // success
		
		} catch (NoSuchAlgorithmException e) {
		
			return false; // not supported
		}
	}
	
	
	/**
	 * Creates a new SRP-6a crypto parameters instance. Note that the 'N'
	 * and 'g' values are not validated, nor is the 'H' support by the
	 * default security provider of the underlying Java runtime.
	 *
	 * @param N A large safe prime for the 'N' parameter. Must not be 
	 *          {@code null}.
	 * @param g A corresponding generator for the 'g' parameter. Must not be
	 *          {@code null}.
	 * @param H A hash algorithm. Must by supported by the default security
	 *          provider of the underlying Java runtime. Must not be 
	 *          {@code null}.
	 */
	public SRP6CryptoParams(final BigInteger N, final BigInteger g, final String H) {
	
		if (N == null)
			throw new NullPointerException("The prime parameter 'N' must not be null");
			
		this.N = N;
		
		if (g == null)
			throw new NullPointerException("The generator parameter 'g' must not be null");
		
		this.g = g;
		
		
		if (H == null || H.isEmpty())
			throw new IllegalArgumentException("Undefined hash algorithm 'H'");

		if (! isSupportedHashAlgorithm(H))
			throw new IllegalArgumentException("Unsupported hash algorithm 'H': " + H);
		
		this.H = H;
	}
	
	
	/**
	 * Returns a new message digest instance for the hash algorithm 'H'.
	 *
	 * @return A new message digest instance or {@code null} if not 
	 *         supported by the default security provider of the underlying
	 *         Java runtime.
	 */
	public MessageDigest getMessageDigestInstance() {
	
		try {
			return MessageDigest.getInstance(H);
		
		} catch (NoSuchAlgorithmException e) {
		
			return null;
		}
	}
}
