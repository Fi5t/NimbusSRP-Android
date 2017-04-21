package com.nimbusds.srp6.cli;

import java.io.IOException;
import java.math.BigInteger;
import java.security.SecureRandom;

import com.nimbusds.srp6.BigIntegerUtils;
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
	 * @throws IOException On console I/O exception.
	 */
	public SRP6Client()
		throws IOException {
	
		super();
	}
	
	
	@Override
	public void run()
		throws IOException, SRP6Exception {
	
		println("*** Nimbus SRP-6a client / verifier generator ***");
		println();
		
		
		// Choose mode
		println("Choose mode: ");
		println("\t1 = generate password verifier");
		println("\t2 = client auth session");
		println();
		print("Your choice [1]: ");
		
		String mode = readInput("1");

		switch (mode) {

			case "1":
				println();
				generatePasswordVerifier();
				break;
			case "2":
				println();
				clientSession();
				break;
			default:
				println("Unknown choice, aborting...");
				break;
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
		
		println("Initialize verifier generator");
		SRP6CryptoParams config = getConfig("\t");
		
		SRP6VerifierGenerator vGen = new SRP6VerifierGenerator(config);
		
		User user = getUser("");
		println();
		
		print("Enter preferred salt 's' byte size [16]: ");
		
		String ss = readInput("16");
		
		int saltBytes;
		
		try {
			saltBytes = Integer.parseInt(ss);
			
		} catch (NumberFormatException e) {
		
			println("Couldn't parse salt 's' byte size: " + e.getMessage());
			return;
		}

		BigInteger s = BigIntegerUtils.bigIntegerFromBytes(vGen.generateRandomSalt(saltBytes, random));
		
		BigInteger v = vGen.generateVerifier(s, user.I, user.P);

		logSalt(BigIntegerUtils.toHex(s));
		println();
		logV(BigIntegerUtils.toHex(v));
	}

	protected void logV(String V) {
		println("Computed password verifier 'v' (hex): " + V);
	}

	protected void logSalt(String s) {
		println("Generated salt 's' (hex): " + s);
	}

	protected SecureRandom random = new SecureRandom();

	/**
	 * Interactive command-line interface to a SRP-6a client authentication
	 * session.
	 *
	 * @throws IOException On a console I/O exception.
	 */
	private void clientSession()
		throws IOException, SRP6Exception {
	
		// Step 1
	
		println("Client session step 1");

		@java.lang.SuppressWarnings("squid:S3599") // DBI
		SRP6ClientSession client = new SRP6ClientSession(){{
			/**
			 * this override is so that JUnit tests can inject a not-so-random insecure generator from the outside.
			 * to be secure simply use SRP6ClientSession without overriding its random generator.
 			 */
			this.random = SRP6Client.this.random;
		}};
		
		User user = getUser("\t");
		client.step1(user.I, user.P);
	
		println();
		
		
		// Step 2
		
		println("Client session step 2");
		
		SRP6CryptoParams config = getConfig("\t");
		
		print("\tEnter salt 's' (hex): ");
		BigInteger s = readBigInteger();
		println();
		
		print("\tEnter public server value 'B' (hex): ");
		BigInteger B = readBigInteger();
		println();
		
		SRP6ClientCredentials cred;
		
		try {
			cred = client.step2(config, s, B);
			
		} catch (SRP6Exception e) {
			
			println(e.getMessage());
			return;
		}

		logA(BigIntegerUtils.toHex(cred.A));
		logM1(BigIntegerUtils.toHex(cred.M1));
		println();
		
		
		// Step 3
		
		println("Client session step 3");
		
		print("\tEnter server evidence message 'M2' (hex): ");
		
		BigInteger M2 = readBigInteger();
		
		try {
			client.step3(M2);
			
		} catch (SRP6Exception e) {
		
			println(e.getMessage());
			throw e;
		}
		
		
		// Success
		println();
		println("Client authentication successfully completed");
		println();
		logS(BigIntegerUtils.toHex(client.getSessionKey()));
		logShash(client.getSessionKeyHash());
	}

	void logM1(String M1) {
		println("\tComputed evidence message 'M1' (hex): " + M1);
	}

	void logA(String A) {
		println("\tComputed public value 'A' (hex): " + A);
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
		
		print(prefix + "Enter user identity 'I': ");
		String I = readInput();
		
		print(prefix + "Enter user password 'P': ");
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
