package com.nimbusds.srp6;


import java.io.Serializable;
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
 * <p>For convenience this class includes a set of precomputed parameters.
 *
 * @author Vladimir Dzhuvinov
 */
public class SRP6CryptoParams implements Serializable {

	/**
	 * SerialVersionUID
	 */
	private static final long serialVersionUID = -8758433435502894107L;

	// Pre-computed primes 'N' for a set of bitsizes
	
	/**
	 * Precomputed safe 256-bit prime 'N', as decimal. Origin SRP-6a demo
	 * at http://srp.stanford.edu/demo/demo.html.
	 */
	public static final BigInteger N_256 = new BigInteger("125617018995153554710546479714086468244499594888726646874671447258204721048803");
	
	
	/**
	 * Precomputed safe 512-bit prime 'N', as decimal. Origin SRP-6a demo
	 * at http://srp.stanford.edu/demo/demo.html.
	 */
	public static final BigInteger N_512 = new BigInteger("11144252439149533417835749556168991736939157778924947037200268358613863350040339017097790259154750906072491181606044774215413467851989724116331597513345603");
	 
	 
	/**
	 * Precomputed safe 768-bit prime 'N', as decimal. Origin SRP-6a demo
	 * at http://srp.stanford.edu/demo/demo.html.
	 */
	public static final BigInteger N_768 = new BigInteger("1087179135105457859072065649059069760280540086975817629066444682366896187793570736574549981488868217843627094867924800342887096064844227836735667168319981288765377499806385489913341488724152562880918438701129530606139552645689583147");
	 
	 
	/**
	 * Precomputed safe 1024-bit prime 'N', as decimal. Origin RFC 5054,
	 * appendix A.
	 */
	public static final BigInteger N_1024 = new BigInteger("167609434410335061345139523764350090260135525329813904557420930309800865859473551531551523800013916573891864789934747039010546328480848979516637673776605610374669426214776197828492691384519453218253702788022233205683635831626913357154941914129985489522629902540768368409482248290641036967659389658897350067939");


	/**
	 * Precomputed safe 1536-bit prime 'N', as decimal. Origin RFC 5054,
	 * appendix A.
	 */
	public static final BigInteger N_1536 = new BigInteger("1486998185923128292816507353619409521152457662596380074614818966810244974827752411420380336514078832314731499938313197533147998565301020797040787428051479639316928015998415709101293902971072960487527411068082311763171549170528008620813391411445907584912865222076100726050255271567749213905330659264908657221124284665444825474741087704974475795505492821585749417639344967192301749033325359286273431675492866492416941152646940908101472416714421046022696100064262587");


        /**
         * Precomputed safe 2048-bit prime 'N', as decimal. Origin RFC 5054,
	 * appendix A.
         */
	public static final BigInteger N_2048 = new BigInteger("21766174458617435773191008891802753781907668374255538511144643224689886235383840957210909013086056401571399717235807266581649606472148410291413364152197364477180887395655483738115072677402235101762521901569820740293149529620419333266262073471054548368736039519702486226506248861060256971802984953561121442680157668000761429988222457090413873973970171927093992114751765168063614761119615476233422096442783117971236371647333871414335895773474667308967050807005509320424799678417036867928316761272274230314067548291133582479583061439577559347101961771406173684378522703483495337037655006751328447510550299250924469288819");


	/**
	 * Generator 'g' parameter for {@link #N_256}, {@link #N_512}, 
	 * {@link #N_768}, {@link #N_1024}, {@link #N_1536}, and
	 * {@link #N_2048} as decimal.
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
	 * Returns an SRP-6a crypto parameters instance with precomputed 'N'
	 * and 'g' values and the specified hash algorithm 'H'.
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

		else if (bitsize == 1536)
			return new SRP6CryptoParams(N_1536, g_common, H);

		else if (bitsize == 2048)
			return new SRP6CryptoParams(N_2048, g_common, H);
		
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
			throw new IllegalArgumentException("The prime parameter 'N' must not be null");
			
		this.N = N;
		
		if (g == null)
			throw new IllegalArgumentException("The generator parameter 'g' must not be null");

		if (g.equals(BigInteger.ONE))
			throw new IllegalArgumentException("The generator parameter 'g' must not be 1");

		if (g.equals(N.subtract(BigInteger.ONE)))
			throw new IllegalArgumentException("The generator parameter 'g' must not equal N - 1");

		if (g.equals(BigInteger.ZERO))
			throw new IllegalArgumentException("The generator parameter 'g' must not be 0");

		
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
