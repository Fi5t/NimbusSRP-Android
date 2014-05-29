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
  
  	// private helper
	function toHex(n) {
		return n.toString(16);
	}
	
	// private helper
	function fromHex(s) {
		return new BigInteger(s, 16);
	}
	
	var _state = 1;
	
	// public initializer
	function init(state) {
		_state = state;
	}
	
	// public getter
	function getState() {
		return _state;
	}
	
    // public
	function generateRandomSalt() {
		return random16byteHex.random();
	}
	
	var x, v;
	
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
	
	// exported api
	return {
		'init': init,
		'getState': getState,
		'generateRandomSalt': generateRandomSalt,
		'generateVerifier': generateVerifier
	};
});