package com.nimbusds.srp6.cli;


import java.io.IOException;
import java.math.BigInteger;
import java.security.SecureRandom;

import com.nimbusds.srp6.BigIntegerUtils;
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

	protected SecureRandom random = new SecureRandom();

	@Override
	public void run()
		throws IOException {
		
		println("*** Nimbus SRP-6a server ***");
		println();
		
		// Step INIT
		println("Initialize server session");
		SRP6CryptoParams config = getConfig("\t");

		@java.lang.SuppressWarnings("squid:S3599") // DBI
		SRP6ServerSession server = new SRP6ServerSession(config){{
			/**
			 * this override is so that JUnit tests ccan inject a not-so-random generator from the outside.
			 * you can just use a vanilla SRP6ServerSession which initialises its own secure random.
			 */
			this.random = SRP6Server.this.random;
		}};
		
		// Step 1
		println("Server session step 1");
		
		print("\tEnter user identity 'I': ");
		String I = readInput();
		
		print("\tEnter password salt 's' (hex): ");
		BigInteger s = readBigInteger();
		
		print("\tEnter password verifier 'v' (hex): ");
		BigInteger v = readBigInteger();
		
		BigInteger B = server.step1(I, s, v);
		
		println();
		logB(BigIntegerUtils.toHex(B));
		println();
		
		
		// Step 2
		println("Server session step 2");
		
		print("\tEnter client public value 'A' (hex): ");
		BigInteger A = readBigInteger();
		
		print("\tEnter client evidence message 'M1' (hex): ");
		BigInteger M1 = readBigInteger();
		
		BigInteger M2;
		
		try {
			M2 = server.step2(A, M1);
			
		} catch (com.nimbusds.srp6.SRP6Exception e) {
		
			println(e.getMessage());
			return;
		}
		
		println();
		logM2(BigIntegerUtils.toHex(M2));

		// Success
		println();
		println("Mutual authentication successfully completed");
		println();
		logS(BigIntegerUtils.toHex(server.getSessionKey()));
		logShash(server.getSessionKeyHash());
	}

	void logM2(String M2) {
		println("\tComputed server evidence message 'M2' (hex): " + M2);
	}

	void logB(String B) {
		println("\tComputed public server value 'B' (hex): " + B);
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
