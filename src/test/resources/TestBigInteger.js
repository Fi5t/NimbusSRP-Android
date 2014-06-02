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

tests({
	jdk17parseIssue: function() {
		var jsClient = new SRP6JavascriptClientSession_N1024_SHA256();
		
		var BB = "b296d9495674cc7015d7c415fff9d4561bc85ded5c594eb558e68c48f42cc80785e93965756eee17b3bc64d04b4c0c9ec9e9db97063488870c3e212bc13e8fb20c3e92d836d9b78f3411363d76253e1b8a381641c7ac47ff44ac5cedbad297ea1f5911238e74ce361896c97ea32253f0c57ddde541652bcb0144dc0d7293764d";
		var kk = "1a1a4c140cde70ae360c1ec33a33155b1022df951732a476a862eb3ab8206a5c";
		
		var B = jsClient.fromHex(BB);
		var k = jsClient.fromHex(kk);
		
		//console.log("B:"+B);
		//console.log("k:"+k);
		
		assert.assertEquals( BB, jsClient.toHex(B));
		assert.assertEquals( kk, jsClient.toHex(k));
	}
		
});

