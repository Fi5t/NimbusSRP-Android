package com.nimbusds.srp6.cli;


import java.io.BufferedReader;
import java.io.IOException;

import java.math.BigInteger;

import com.nimbusds.srp6.Hex;
import com.nimbusds.srp6.SRP6ClientCredentials;
import com.nimbusds.srp6.SRP6ClientSession;
import com.nimbusds.srp6.SRP6CryptoParams;
import com.nimbusds.srp6.SRP6Exception;
import com.nimbusds.srp6.SRP6VerifierGenerator;


/**
 * Interactive command-line client and verifier generator for Secure Remote 
 * Password (SRP-6a) authentication. Can be used to test and debug server-side 
 * SRP-6a authentication.
 *
 * <p>Uses the default Nimbus SRP {@link com.nimbusds.srp6.SRP6Routines routines}
 * for computing the password key 'x', the server and client evidence messages 
 * ('M1' and 'M2').
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2011-11-28)
 */
public class SRP6Client extends SRP6Tool {


	/**
	 * User identity 'I' and password 'P'.
	 */
	public static class User {
	
		
		/**
		 * The user identity 'I'.
		 */
		public final String I;
		
		
		/**
		 * The user password 'P'.
		 */
		public final String P;
		
		
		/**
		 * Creates a new user identity 'I' and 'P'.
		 *
		 * @param I The user identity 'I'.
		 * @param P The user password 'P'.
		 */
		public User(final String I, final String P) {
		
			this.I = I;
			this.P = P;
		}
	}
	
	
	/**
	 * Creates a new SRP-6a command-line client and verifier generator.
	 */
	public SRP6Client()
		throws IOException {
	
		super();
	}
	
	
	/**
	 * @inheritDoc
	 */
	public void run()
		throws IOException {
	
		System.out.println("*** Nimbus SRP-6a client / verifier generator ***");
		System.out.println();
		
		
		// Choose mode
		System.out.println("Choose mode: ");
		System.out.println("\t1 = generate password verifier");
		System.out.println("\t2 = client auth session");
		System.out.println();
		System.out.print("Your choice [1]: ");
		
		String mode = readInput("1");
		
		if (mode.equals("1")) {
			
			System.out.println();
			generatePasswordVerifier();
		}
		else if (mode.equals("2")) {
		
			System.out.println();
			clientSession();
		}
		else {
			System.out.println("Unknown choice, aborting...");
			return;
		}
	}
	
	
	/**
	 * Interactive command-line interface to generate a new password 
	 * verifier.
	 *
	 * @throws IOException On missing / bad input or console I/O exception.
	 */
	private void generatePasswordVerifier()
		throws IOException {
		
		System.out.println("Initialize verifier generator");
		SRP6CryptoParams config = getConfig("\t");
		
		SRP6VerifierGenerator vGen = new SRP6VerifierGenerator(config);
		
		User user = getUser("");
		System.out.println();
		
		System.out.print("Enter preferred salt 's' byte size [16]: ");
		
		String ss = readInput("16");
		
		int saltBytes = 0;
		
		try {
			saltBytes = Integer.parseInt(ss);
			
		} catch (NumberFormatException e) {
		
			System.out.println("Couldn't parse salt 's' byte size: " + e.getMessage());
			return;
		}
		
		BigInteger s = new BigInteger(1, SRP6VerifierGenerator.generateRandomSalt(saltBytes));
		
		BigInteger v = vGen.generateVerifier(s, user.I, user.P);
		
		System.out.println("Generated salt 's' (hex): " + Hex.encode(s));
		System.out.println();
		System.out.println("Computed password verifier 'v' (hex): " + Hex.encode(v));
	}
	
	
	/**
	 * Interactive command-line interface to a SRP-6a client authentication
	 * session.
	 *
	 * @throws IOException On a console I/O exception.
	 */
	private void clientSession()
		throws IOException {
	
		// Step 1
	
		System.out.println("Client session step 1");
		
		SRP6ClientSession client = new SRP6ClientSession();
		
		User user = getUser("\t");
		client.step1(user.I, user.P);
	
		System.out.println();
		
		
		// Step 2
		
		System.out.println("Client session step 2");
		
		SRP6CryptoParams config = getConfig("\t");
		
		System.out.print("\tEnter salt 's' (hex): ");
		BigInteger s = readBigInteger();
		System.out.println();
		
		System.out.print("\tEnter public server value 'B' (hex): ");
		BigInteger B = readBigInteger();
		System.out.println();
		
		SRP6ClientCredentials cred = null;
		
		try {
			cred = client.step2(config, s, B);
			
		} catch (SRP6Exception e) {
			
			System.out.println(e.getMessage());
			return;
		}
		
		System.out.println("\tComputed public value 'A' (hex): " + Hex.encode(cred.A));
		System.out.println("\tComputed evidence message 'M1' (hex): " + Hex.encode(cred.M1));
		System.out.println();
		
		
		// Step 3
		
		System.out.println("Client session step 3");
		
		System.out.print("\tEnter server evidence message 'M2' (hex): ");
		
		BigInteger M2 = readBigInteger();
		
		try {
			client.step3(M2);
			
		} catch (SRP6Exception e) {
		
			System.out.println(e.getMessage());
			return;
		}
		
		
		// Success
		System.out.println();
		System.out.println("Client authentication successfully completed");
	}
	
	
	/**
	 * Interactive command-line session to obtain the user identity 'I' and
	 * password 'P'.
	 *
	 * @param prefix String to prepend to the console output.
	 *
	 * @return The user identity 'I' and password 'P'.
	 *
	 * @throws IOException On a console I/O exception.
	 */
	private User getUser(final String prefix)
		throws IOException {
		
		System.out.print(prefix + "Enter user identity 'I': ");
		String I = readInput();
		
		System.out.print(prefix + "Enter user password 'P': ");
		String P = readInput();
		
		return new User(I, P);
	}
	
	

	/**
	 * The main entry point to the command-line SRP-6a client and verifier
	 * generator.
	 *
	 * @param args The command line arguments.
	 *
	 * @throws Exception On a CLI or SRP-6a exception.
	 */
	public static void main(final String[] args)
		throws Exception {
	
		SRP6Client client = new SRP6Client();
		
		client.run();
	}
}
