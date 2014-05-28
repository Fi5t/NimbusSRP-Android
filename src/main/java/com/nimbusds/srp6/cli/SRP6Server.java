package com.nimbusds.srp6.cli;


import java.io.IOException;
import java.math.BigInteger;

import com.nimbusds.srp6.Hex;
import com.nimbusds.srp6.SRP6CryptoParams;
import com.nimbusds.srp6.SRP6ServerSession;


/**
 * Interactive command-line server for Secure Remote Password (SRP-6a) 
 * authentication. Can be used to test and debug client-side SRP-6a 
 * authentication.
 *
 * <p>Uses the default Nimbus SRP {@link com.nimbusds.srp6.SRP6Routines routines}
 * for computing the password key 'x', the server and client evidence messages 
 * ('M1' and 'M2').
 *
 * @author Vladimir Dzhuvinov
 */
public class SRP6Server extends SRP6Tool {


	/**
	 * Creates a new SRP-6a command-line server.
	 */
	public SRP6Server()
		throws IOException {
	
		super();
	}
	
	
	/**
	 * {@inheritDoc}
	 */
	public void run()
		throws IOException {
		
		System.out.println("*** Nimbus SRP-6a server ***");
		System.out.println();
		
		// Step INIT
		System.out.println("Initialize server session");
		SRP6CryptoParams config = getConfig("\t");
		
		SRP6ServerSession server = new SRP6ServerSession(config);
		
		
		// Step 1
		System.out.println("Server session step 1");
		
		System.out.print("\tEnter user identity 'I': ");
		String I = readInput();
		
		System.out.print("\tEnter password salt 's' (hex): ");
		BigInteger s = readBigInteger();
		
		System.out.print("\tEnter password verifier 'v' (hex): ");
		BigInteger v = readBigInteger();
		
		BigInteger B = server.step1(I, s, v);
		
		System.out.println();
		System.out.println("\tComputed public server value 'B' (hex): " + Hex.encode(B));
		System.out.println();
		
		
		// Step 2
		System.out.println("Server session step 2");
		
		System.out.print("\tEnter client public value 'A' (hex): ");
		BigInteger A = readBigInteger();
		
		System.out.print("\tEnter client evidence message 'M1' (hex): ");
		BigInteger M1 = readBigInteger();
		
		BigInteger M2 = null;
		
		try {
			M2 = server.step2(A, M1);
			
		} catch (com.nimbusds.srp6.SRP6Exception e) {
		
			System.out.println(e.getMessage());
			return;
		}
		
		System.out.println();
		System.out.println("\tComputed server evidence message 'M2 (hex): " + Hex.encode(M2));
		
		// Success
		System.out.println();
		System.out.println("Mutual authentication successfully completed");
	}
	
	
	/**
	 * The main entry point to the command-line SRP-6a server.
	 *
	 * @param args The command line arguments.
	 *
	 * @throws Exception On a CLI or SRP-6a exception.
	 */
	public static void main(final String[] args)
		throws Exception {
	
		SRP6Server server = new SRP6Server();
		
		server.run();
	}
}
