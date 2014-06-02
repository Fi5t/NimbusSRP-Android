// import test untils
load("src/test/resources/JsUnitUtils.js");

// no need to warm up the fallback random number generator when testing
var test_random16byteHexAdvance = 0;

// import collaborators
load("src/main/resources/biginteger.js");
load("src/main/resources/sha256.js");
load("src/main/resources/isaac.js");
load("src/main/resources/random.js");

// import script under test
load("src/main/resources/nimbus-srp6client.js");

var salt = "132ce4591a29220827c6198169ea4320";
var username = "tom@arcot.com";
var password = "password1234";

// we test the javascript client verifier generation against work-alike test java
var javaMockClient = Packages.com.nimbusds.srp6.js.TestDouble_N1024_SHA256;

// we test against the java session which uses the same string concat hashing as the javascript client
var javaServerSession = Packages.com.nimbusds.srp6.js.SRP6JavascriptServerSession_N1024_SHA256;

function fromHex(h) {
	return new BigInteger(h, 16);
}

tests({

	saltSanityCheck: function() {
		var jsClientSession = SRP6JavascriptClientSession_N1024_SHA256();
		var randoms = [];
		for( var i = 0; i < 10; i++ ) {
			var r = jsClientSession.generateRandomSalt();
			//console.log(r);
			assert.assertTrue(r.length > 0);
			randoms.push(r);
			for( var j = i - 1; j - 1 > 0; j-- ) {
				var other = randoms[j];
				assert.assertTrue(r != other); 
			}
		}
	}, 
	
	testVerifierInputs: function() {
		var jsClientSession = SRP6JavascriptClientSession_N1024_SHA256();
		try {
			jsClientSession.generateVerifier(null, username, password);
			fail();
		} catch(e){}
		try {
			jsClientSession.generateVerifier(salt, null, password);
			fail();
		} catch(e){}		 
		try {
			jsClientSession.generateVerifier(salt, username, null);
			fail();
		} catch(e){}	
		try {
			jsClientSession.generateVerifier("", username, password);
			fail();
		} catch(e){}
		try {
			jsClientSession.generateVerifier(salt, "", password);
			fail();
		} catch(e){}		 
		try {
			jsClientSession.generateVerifier(salt, username, "");
			fail();
		} catch(e){}			
		try {
			jsClientSession.generateVerifier(salt, username);
			fail();
		} catch(e){}
		try {
			jsClientSession.generateVerifier(salt);
			fail();
		} catch(e){}		 
		try {
			jsClientSession.generateVerifier();
			fail();
		} catch(e){}					
	},
	
	/**
	Here check the js verifier code against a java work-alike and sanity check both 
	have same size hex output as the original nimbus routine. 
    */
	verifierTest: function() {
		var javaClientSession = new javaMockClient();
		var jsClientSession = SRP6JavascriptClientSession_N1024_SHA256();

		// main nimbus client version
		var javaV = ""+javaClientSession.generateVerifier(salt, username, password);
		//console.log("javaV:"+javaV);

		// js nimbus client version
		var jsV = jsClientSession.generateVerifier(salt, username, password);
		//console.log("jsV  :"+javaV);

		// check that they are same order of magnitude hex		
		jsAssert.assertIntegerEquals(javaV.length, jsV.length);
		
		// actual java work-alike of string concat hash routine in javascript
		var javaV2 = javaClientSession.generateVerifierJavascriptAlgorithm(salt, username, password);
		//console.log("javaV2:"+javaV2);
		
		// assert that the javascript verifier values is matches the java work-alike 
		assert.assertEquals(javaV2, jsV);
	}, 
	
	/**
	Tests the full flow between the Javascript Client Session and the Java Server Session
	*/
	testMutualAuthentiation: function() {
	
		var client = SRP6JavascriptClientSession_N1024_SHA256();
		
		var v = client.generateVerifier(salt, username, password);
		client.step1(username,password);
		
		var server = new javaServerSession();
		var B = server.step1(username, salt, v);
		
		var credentials = client.step2(salt, B, javaServerSession.k);
		
		//console.log("A:"+credentials.A);
		//console.log("M1:"+credentials.M1);
		
		var M2 = server.step2(credentials.A, credentials.M1);
		
		client.step3(M2);
	}
	
});

