package com.nimbusds.srp6.cli;


import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.IOException;

import java.math.BigInteger;

import com.nimbusds.srp6.BigIntegerUtils;
import com.nimbusds.srp6.SRP6CryptoParams;
import com.nimbusds.srp6.SRP6Exception;


/**
 * The base abstract class for the interactive command-line SRP-6a tools.
 *
 * @author Vladimir Dzhuvinov
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
	
		BigInteger bigInt = BigIntegerUtils.fromHex(readInput());
		
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
		
		println(prefix + "Enter prime 'N' (hex): ");
		
		println(prefix + "\t1 = select precomputed 256-bit");
		println(prefix + "\t2 = select precomputed 512-bit");
		println(prefix + "\t3 = select precomputed 768-bit");
		println(prefix + "\t4 = select precomputed 1024-bit");
		println(prefix + "\t5 = select precomputed 2048-bit");
		println(prefix + "\t6 = enter prime 'N' and generator 'g'");
		println();
		print(prefix + "Your choice [1]: ");
		
		String choice = readInput("1");
		
		BigInteger N;
		BigInteger g;
		
		boolean selectedPrecomputed = true;

		switch (choice) {

			case "1":
				N = SRP6CryptoParams.N_256;
				g = SRP6CryptoParams.g_common;
				break;
			case "2":
				N = SRP6CryptoParams.N_512;
				g = SRP6CryptoParams.g_common;
				break;
			case "3":
				N = SRP6CryptoParams.N_768;
				g = SRP6CryptoParams.g_common;
				break;
			case "4":
				N = SRP6CryptoParams.N_1024;
				g = SRP6CryptoParams.g_common;
				break;
			case "5":
				N = SRP6CryptoParams.N_2048;
				g = SRP6CryptoParams.g_common;
				break;
			case "6":
				println();
				print(prefix + "Enter prime 'N' (hex): ");
				N = readBigInteger();
				print(prefix + "Enter generator 'g' (hex): ");
				g = readBigInteger();
				selectedPrecomputed = false;
				break;
			default:
				throw new IOException("Unknown choice");
		}
		
		println();
		
		if (selectedPrecomputed) {
			println(prefix + "Selected prime 'N' (hex): " + BigIntegerUtils.toHex(N));
			println(prefix + "Selected generator 'g' (hex): " + BigIntegerUtils.toHex(g));
			println();
		}
		
		print(prefix + "Enter hash algorithm 'H' [SHA-1]: ");
		String H = readInput("SHA-1");
		println();
		
		return new SRP6CryptoParams(N, g, H);
	}

	protected void println() {
		System.out.println();
	}

	protected void print(String s) {
		System.out.print(s);
	}

	protected void println(String msg){
		println(msg);
	}

	void logShash(byte[] sessionKeyHash) {
		println("\tHashed shared key 'H(S)' (hex): " + javax.xml.bind.DatatypeConverter.printHexBinary(sessionKeyHash));
	}

	void logS(String S) {
		println("\tComputed shared key 'S' (hex): " + S);
	}


	/**
	 * Runs the SRP-6a command-line tool.
	 *
	 * @throws IOException On missing / bad input or console I/O exception.
	 */
	public abstract void run() throws IOException, SRP6Exception;

}
