package com.nimbusds.srp6;


import java.math.BigInteger;


/**
 * Hexadecimal encoding and decoding utility.
 *
 * <p>Obtained from Apache Xerces and Aduna Software code on java2s.com.
 *
 * @author <a href="http://dzhuvinov.com">Vladimir Dzhuvinov</a>
 * @version 1.3 (2012-07-30)
 */
public class Hex {

	static private final int  BASELENGTH   = 128;
	
	static private final int  LOOKUPLENGTH = 16;
	
	static final private byte [] hexNumberTable    = new byte[BASELENGTH];


	static {
		for (int i = 0; i < BASELENGTH; i++ ) {
			hexNumberTable[i] = -1;
		}
		for ( int i = '9'; i >= '0'; i--) {
			hexNumberTable[i] = (byte) (i-'0');
		}
		for ( int i = 'F'; i>= 'A'; i--) {
			hexNumberTable[i] = (byte) ( i-'A' + 10 );
		}
		for ( int i = 'f'; i>= 'a'; i--) {
			hexNumberTable[i] = (byte) ( i-'a' + 10 );
		}
	}
	
	
	/**
	 * Encodes the specified byte array into a hex string. The resulting
	 * string always uses two hexadecimals per byte. As a result, the length
	 * of the resulting string is guaranteed to be twice the length of the
	 * supplied byte array.
	 *
	 * @param bytes The byte array to encode.
	 *
	 * @return The resulting hex encoded string or {@code null} if the input
	 *         is undefined.
	 */
	public static String encode(final byte[] bytes) {
	
		StringBuilder sb = new StringBuilder(2 * bytes.length);

		for (int i = 0; i < bytes.length; i++) {
		
			String hex = Integer.toHexString(bytes[i] & 0xff);

			if (hex.length() == 1)
				sb.append('0');
				
			sb.append(hex);
    		}

		return sb.toString();
  	}
	
	
	/**
	 * Encodes the specified big integer into a hex string.
	 *
	 * @return The resulting hex encoded string or {@code null} if the input
	 *         is undefined.
	 */
	public static String encode(final BigInteger bigint) {
	
		if (bigint == null)
			return null;
	
		return bigint.toString(16);
	}

	
	/**
	 * Decodes the specified hex string into a byte array.
	 *
	 * @param hex The hex encoded string to decode.
	 *
	 * @return The resulting byte array or {@code null} if decoding failed.
	 */
	public static byte[] decodeToByteArray(final String hex) {

		if (hex == null)
			return null;
		
		int lengthData = hex.length();
	
		if (lengthData % 2 != 0)
			return null;

		char[] binaryData = hex.toCharArray();
		int lengthDecode = lengthData / 2;
		byte[] decodedData = new byte[lengthDecode];
		byte temp1, temp2;
		char tempChar;
		
		for( int i = 0; i<lengthDecode; i++ ){
		
			tempChar = binaryData[i*2];
			temp1 = (tempChar < BASELENGTH) ? hexNumberTable[tempChar] : -1;
		
			if (temp1 == -1)
				return null;
		
			tempChar = binaryData[i*2+1];
			temp2 = (tempChar < BASELENGTH) ? hexNumberTable[tempChar] : -1;
		
			if (temp2 == -1)
				return null;
		
			decodedData[i] = (byte)((temp1 << 4) | temp2);
		}
		
		return decodedData;
	}
	
	
	/**
	 * Decodes the specified hex string into a big integer.
	 *
	 * @param hex The hex encoded string to decode.
	 *
	 * @return The resulting big integer or {@code null} if decoding failed.
	 */
	public static BigInteger decodeToBigInteger(final String hex) {
	
		if (hex == null)
			return null;
	
		try {
			return new BigInteger(hex, 16);
			
		} catch (NumberFormatException e) {
		
			return null;
		}
	}
	
	
	/**
	 * Prevents instantiation.
	 */
	private Hex() {
	
		// do nothing
	}
}
