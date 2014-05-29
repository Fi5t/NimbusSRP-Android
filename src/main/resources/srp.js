/*
Copyright (c) 2000-2014 The Legion of the Bouncy Castle Inc. (http://www.bouncycastle.org)

Permission is hereby granted, free of charge, to any person obtaining a copy of this software 
and associated documentation files (the "Software"), to deal in the Software without restriction, 
including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, 
and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so,
subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial
portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR
PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
DEALINGS IN THE SOFTWARE.
*/

var sN_1024 = "EEAF0AB9ADB38DD69C33F80AFA8FC5E86072618775FF3C0B9EA2314C9C256576D674DF7496EA81D3383B4813D692C6E0E0D5D8E250B98BE48E495C1D6089DAD15DC7D7B46154D6B6CE8EF4AD69B15D4982559B297BCF1885C529F566660E57EC68EDBC3C05726CC02FD4CBF4976EAA9AFD5138FE8376435B9FC61D2FC0EB06E3";
var sg_1024 = "2";

var SrpClientSession = (function(){

	var N, g, v, A, b, B, u, S, x, a, m1, m2;

	// TODO pass in hash function
	var H = function (x) {
		return SHA256(x).toLowerCase();
	}
  
	function toHex(n) {
		return n.toString(16).toUpperCase();
	}
	
	function fromHex(s) {
		return new BigInteger(s.toUpperCase(), 16);
	}
  
	// public init
	function init(NN, gg) {
		N = fromHex(NN);
		g = fromHex(gg);
	}

	// private generateX do not pass 'aa' outside of synthetic tests
	function generateX(salt, identity, password) {
		var hash1 = H(identity+':'+password);
		
		var hashStr = salt+hash1;
		
		var hash = H(hashStr.toUpperCase());

		x = fromHex(hash).mod(N);
	}

	// public. do not pass 'aa' which is the ephemeral key unless running unit tests
	function generateClientCredentials(aa) {
		if( typeof aa == 'undefined' ) { // allow the user of none random for testing
			var r = random16byteHex.random();
			a = fromHex(r);
		} else {
			console.log("WARNING: YOU SHOULD NOT HIT THIS LINE IN BROWSER it is for testing Javascript via Java only. Do not pass 'aa'!");
			a = fromHex(aa);
		}
	
		A = g.modPow(a, N); 
		
		return toHex(A);
	}
	
	// public. do not pass 'aa' which is the ephemeral key unless running unit tests
	function generateVerifier(salt, identity, password, aa){
		if( typeof aa == 'undefined' ) { // allow the user of none random for testing
			var r = random16byteHex.random();
			a = fromHex(r);
		} else {
			console.log("WARNING: YOU SHOULD NOT HIT THIS LINE IN BROWSER it is for testing Javascript via Java only. Do not pass 'aa'!");
			a = fromHex(aa);
		}
	
		generateX(salt, identity, password);
		
		v = g.modPow(x, N);
		
		return toHex(v);
	}
	
	// public 
	function calculateSecret(serverBB, salt, identity, password) {
		generateX(salt, identity, password, aa);
	
		var serverB = fromHex(serverBB);
		var serverBmodN = serverB.mod(N);
		// Check that val % N != 0
		if( toHex(serverBmodN) == "0") {
			throw new Error("Invalid public value: B.mod(N)==0");
		} 
		B = serverBmodN;
		var hash = H(toHex(A) + toHex(B));
		u = fromHex(hash);
		var hash1 = H(toHex(N) + toHex(g));
		k = fromHex(hash1);
		var exp = u.multiply(x).add(a);
		var tmp = g.modPow(x, N).multiply(k).mod(N);
		var tmp2 = B.subtract(tmp).mod(N);
		S = tmp2.modPow(exp, N);
		/*
		println("jsx:" + toHex(x));
		println("jsN:" + toHex(N));
		println("jsB:" + toHex(B));
		println("jsA:" + toHex(A));
		println("jsu:" + toHex(u));
		println("jsv:" + toHex(v));
		println("jsk:" + toHex(k));
		println("jsa:" + toHex(a));
		println("jsexp:" + toHex(exp));
		println("jstmp:" + toHex(tmp));
		println("jstmp2:" + toHex(tmp2));
		println("jsS:" + toHex(S));
		*/
	}
	
	// public
	function generateSecretHashM1() {
		var m1str = H(toHex(A)+toHex(B)+toHex(S));
		m1 = m1str.toUpperCase();
		//println("jsM1:" + m1);
		var m2Str = H(toHex(A)+toHex(m1)+toHex(S));
		m2 = m2Str.toUpperCase();
		//println("jsM2:" + m2);
		return m1;
	}
	
	// public
	function validateSessionHashM2(sm2) {
		if( m2.toUpperCase() != sm2.toUpperCase() ) {
			throw new Error("Server hash does not match.\nm2"+m2+"\nsm2:"+sm2);
		} 
	}
	
	// public
	function startExchange() {
		return toHex(v);
	}
		
	/* return object with public api */
	return {
		'init': init,
		'generateClientCredentials': generateClientCredentials,
		'generateVerifier': generateVerifier,
		'calculateSecret': calculateSecret,
		'generateSecretHashM1': generateSecretHashM1,
		'validateSessionHashM2': validateSessionHashM2
	};

})(); /* singleton */
