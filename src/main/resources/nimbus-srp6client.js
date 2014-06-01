/*
The MIT License (MIT) http://opensource.org/licenses/MIT

Copyright (c) 2014  Simon Massey

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/
/**
Javascript client which speaks hex strings, users a 1024 bit N, SHA256
and which speaks hex strings. It uses random 16 byte hex strings as random 
key 'a'. On the server use the matching java class: 
	com.nimbusds.srp6.js.SRP6JavascriptServerSession_N1024_SHA256 
*/
var SRP6JavascriptClientSession_N1024_SHA256 = (function(){
	var N_1024 = new BigInteger("167609434410335061345139523764350090260135525329813904557420930309800865859473551531551523800013916573891864789934747039010546328480848979516637673776605610374669426214776197828492691384519453218253702788022233205683635831626913357154941914129985489522629902540768368409482248290641036967659389658897350067939", 10);
	var g_common = new BigInteger("2", 10);
	
	// N, g and H must match server session
	var N = N_1024;
	var g = g_common; 
	var H = function (x) {
		return SHA256(x).toLowerCase();
	}
  
	/**
	 * The session is initialised and ready to begin authentication
	 * by proceeding to {@link #STEP_1}.
	 */
	var INIT = 0;
		
	/**
	 * The authenticating user has input their identity 'I' 
	 * (username) and password 'P'. The session is ready to proceed
	 * to {@link #STEP_2}.
	 */
	var STEP_1 = 1;
		
	/**
	 * The user identity 'I' is submitted to the server which has 
	 * replied with the matching salt 's' and its public value 'B' 
	 * based on the user's password verifier 'v'. The session is 
	 * ready to proceed to {@link #STEP_3}.
	 */
	var STEP_2 = 2;
		
	/**
	 * The client public key 'A' and evidence message 'M1' are
	 * submitted and the server has replied with own evidence
	 * message 'M2'. The session is finished (authentication was 
	 * successful or failed).
	 */
	var STEP_3 = 3;
  
  	// public helper
	function toHex(n) {
		return n.toString(16);
	}
	
	// public helper
	function fromHex(s) {
		return new BigInteger(s, 16);
	}
	
	var state = INIT;
	
	// public initializer
	function init(_state) {
		state = _state;
	}
	
	// public getter
	function getState() {
		return state;
	}
	
    // public
	function generateRandomSalt() {
		return random16byteHex.random();
	}
	
	var x, v, I, P;
	
	// private
	function check(v, name) {
		if( typeof v == 'undefined' || v == null || v == "" ) {
			throw new Error(name+" must not be null or empty");
		}
	}
	
	/** private<p>
	 * 
	 * Computes x = H(s | H(I | ":" | P))
	 * <p>Specification is RFC 5054  
	 *
	 * @param salt     The salt 's'. Must not be null or empty.
	 * @param identity The user identity/email 'I'. Must not be null or empty.
	 * @param password The user password 'P'. Must not be null or empty
	 * @return The resulting 'x' value.
	 */
	function generateX(salt, identity, password) {
		check(salt, "salt");
		check(identity, "identity");
		check(password, "password");
		var hash1 = H(identity+':'+password);
		var hashStr = salt+hash1;
		var hash = H(hashStr.toUpperCase());
		x = fromHex(hash).mod(N);
		return x;
	}
	
	/* public<p>
	 * 
	 * Generates a new verifier 'v' from the specified parameters.
	 * <p>The verifier is computed as v = g^x (mod N). 
	 *
	 * @param salt     The salt 's'. Must not be null or empty.
	 * @param identity The user identity/email 'I'. Must not be null or empty.
	 * @param password The user password 'P'. Must not be null or empty
	 * @return The resulting verifier 'v' as a hex string
	 */
	function generateVerifier(salt, identity, password) {
		var x = generateX(salt, identity, password);
		v = g.modPow(x, N);
		return toHex(v);
	}
	
	/**
	 * Records the identity 'I' and password 'P' of the authenticating user.
	 * The session is incremented to {@link State#STEP_1}.
	 * <p>Argument origin:
	 * <ul>
	 *     <li>From user: user identity 'I' and password 'P'.
	 * </ul>
	 * @param userID   The identity 'I' of the authenticating user, UTF-8
	 *                 encoded. Must not be {@code null} or empty.
	 * @param password The user password 'P', UTF-8 encoded. Must not be
	 *                 {@code null}.
	 * @throws IllegalStateException If the method is invoked in a state 
	 *                               other than {@link State#INIT}.
	 */
	function step1(identity, password) {
		check(identity, "identity");
		check(password, "password");
		I = identity;
		P = password;
		if( state != INIT ) {
		  throw new Error("IllegalStateException not in state INIT");
		}
		state = STEP_1;
	}
	
	var s, B, A, a, k;
	
	/**
	 * Receives the password salt 's' and public value 'B' from the server.
	 * The SRP-6a crypto parameters are also set. The session is incremented
	 * to {@link State#STEP_2}.
	 * <p>Argument origin:
	 * <ul>
	 *     <li>From server: password salt 's', public value 'B'.
	 *     <li>Pre-agreed: crypto parameters prime 'N', 
	 *         generator 'g' and hash function 'H'.
	 * </ul>
	 * @param s      The password salt 's'. Must not be {@code null}.
	 * @param B      The public server value 'B'. Must not be {@code null}.
	 * @param k      k is H(N,g) with padding by the server. Must not be {@code null}.
	 * @return The client credentials consisting of the client public key 
	 *         'A' and the client evidence message 'M1'.
	 * @throws IllegalStateException If the method is invoked in a state 
	 *                               other than {@link State#STEP_1}.
	 * @throws SRP6Exception         If the public server value 'B' is invalid.
	 */
	function step2(ss, BB, kk) {
		check(ss);
		check(BB);
		check(kk);
		s = ss;
		B = BB;
		k = kk;
		var x = generateX(s, I, P);
		// 1024 bit N implies 512 bit key implies 2 x 16byte random implies twice salt generation
		var aStr = generateRandomSalt() + generateRandomSalt();
		a = fromHex(aStr);
		A = g.modPow(a, N);
		
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
	function getPadded(bi, length) {
		var bytes = bi.toByteArray();
		var unsignedBytes = [];
		var stripLeading = true;
		for( var i = 0; i < bytes.length; i++ ) {
			var b = bytes[i];
			if( stripLeading && b == 0 ) {
				// to nothing
			} else {
				unsignedBytes.push(b);
				stripLeading = false;
			}
		}
		var padded = unsignedBytes;
		if( unsignedBytes.length < length ) {
			// TODO add padding but not actually required for sha256,N_1024,G_2 case
			
		} 
		return padded;
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
	 function computeU(Astr, Bstr) {
	 	check(Astr);
	 	check(Bstr);
		var A = fromHex(Astr);
		var B = fromHex(Bstr);
		var Abin = getPadded(A, 128);
		var Bbin = getPadded(B, 128);
		
		var concat = [];
		
		for( var i = 0; i < Abin.length; i++ ) {
			concat.push(Abin[i]);
		}

		for( var i = 0; i < Bbin.length; i++ ) {
			concat.push(Bbin[i]);
		}

		var output = moduleSHA256.hashBinaryArray(concat, concat.length);

		return output;
	}
	
	// exported api
	return {
		'toHex': toHex,
		'fromHex': fromHex,
		'init': init,
		'getState': getState,
		'generateRandomSalt': generateRandomSalt,
		'generateVerifier': generateVerifier,
		'computeU': computeU,
		'step1': step1,
		'step2': step2
	};
});