package com.nimbusds.srp6.cli;


import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.IOException;

import java.math.BigInteger;

import com.nimbusds.srp6.Hex;
import com.nimbusds.srp6.SRP6CryptoParams;


/**
 * The base abstract class for the interactive command-line SRP-6a tools.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2011-11-28)
 */
public abstract class SRP6Tool {


	/**
	 * Buffered console input reader.
	 */
	protected BufferedReader console;
	
	
	/**
	 * Creates a new SRP-6a command-line tool.
	 *
	 * @throws IOException On console I/O exception.
	 */
	public SRP6Tool()
		throws IOException {
	
		// Prepare console input
		InputStreamReader stdin = new InputStreamReader(System.in);
		console = new BufferedReader(stdin);
	}
	
	
	/**
	 * Reads user input from the command-line.
	 *
	 * @param def The default string to return if nothing was entered by the
	 *            user, {@code null} if user input is mandatory.
	 *
	 * @return The input string (trimmed).
	 *
	 * @throws IOException On missing input or console I/O exception.
	 */
	public String readInput(final String def)
		throws IOException {
		
		String input = console.readLine();
		
		if (input == null || input.isEmpty()) {
			
			if (def != null)
				return def;
			
			else
				throw new IOException("Missing input");
		}
		
		return input.trim();
	}
	
	
	/**
	 * Reads user input from the command-line.
	 *
	 * @return The input string (trimmed).
	 *
	 * @throws IOException On missing input or console I/O exception.
	 */
	public String readInput()
		throws IOException {
		
		return readInput(null);
	}
	
	
	/**
	 * Reads a big integer (hex-encoded) from the command-line.
	 *
	 * @return The input big integer.
	 *
	 * @throws IOException On missing input, bad hex format or console I/O
	 *                     exception.
	 */
	public BigInteger readBigInteger()
		throws IOException {
	
		BigInteger bigInt = Hex.decodeToBigInteger(readInput());
		
		if (bigInt == null)
			throw new IOException("Bad hex encoding");
			
		return bigInt;
	}
	
	
	/**
	 * Interactive command-line session to select the SRP-6a crypto 
	 * parameters.
	 *
	 * @param prefix String to prepend to the console output.
	 *
	 * @return SRP6CryptoParams The SRP-6a crypto parameters.
	 *
	 * @throws IOException On a console I/O exception.
	 */
	public SRP6CryptoParams getConfig(final String prefix)
		throws IOException {
		
		System.out.println(prefix + "Enter prime 'N' (hex): ");
		
		System.out.println(prefix + "\t1 = select precomputed 256-bit");
		System.out.println(prefix + "\t2 = select precomputed 512-bit");
		System.out.println(prefix + "\t3 = select precomputed 768-bit");
		System.out.println(prefix + "\t4 = select precomputed 1024-bit");
		System.out.println(prefix + "\t5 = enter prime 'N' and generator 'g'");
		System.out.println();
		System.out.print(prefix + "Your choice [1]: ");
		
		String choice = readInput("1");
		
		BigInteger N = null;
		BigInteger g = null;
		
		boolean selectedPrecomputed = true;
		
		if (choice.equals("1")) {
			N = SRP6CryptoParams.N_256;
			g = SRP6CryptoParams.g_common;
		}
		else if (choice.equals("2")) {
			N = SRP6CryptoParams.N_512;
			g = SRP6CryptoParams.g_common;
		}
		else if (choice.equals("3")) {
			N = SRP6CryptoParams.N_768;
			g = SRP6CryptoParams.g_common;
		}
		else if (choice.equals("4")) {
			N = SRP6CryptoParams.N_1024;
			g = SRP6CryptoParams.g_common;
		}
		else if (choice.equals("5")) {
			
			System.out.println();
			
			System.out.print(prefix + "Enter prime 'N' (hex): ");
			N = readBigInteger();
			
			System.out.print(prefix + "Enter generator 'g' (hex): ");
			g = readBigInteger();
			
			selectedPrecomputed = false;
		}
		else {
			throw new IOException("Unknown choice");
		}
		
		System.out.println();
		
		if (selectedPrecomputed) {
			System.out.println(prefix + "Selected prime 'N' (hex): " + Hex.encode(N));
			System.out.println(prefix + "Selected generator 'g' (hex): " + Hex.encode(g));
			System.out.println();
		}
		
		System.out.print(prefix + "Enter hash algorithm 'H' [SHA-1]: ");
		String H = readInput("SHA-1");
		System.out.println();
		
		return new SRP6CryptoParams(N, g, H);
	}
	
	
	/**
	 * Runs the SRP-6a command-line tool.
	 *
	 * @throws IOException On missing / bad input or console I/O exception.
	 */
	public abstract void run() throws IOException;

}
