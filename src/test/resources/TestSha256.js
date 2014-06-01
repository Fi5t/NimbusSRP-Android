
// import test untils
load("src/test/resources/JsUnitUtils.js");

load("src/main/resources/biginteger.js");
load("src/main/resources/sha256.js");

var javaConstants = Packages.com.nimbusds.srp6.js.Constants;

tests({

	hashingStringTest: function() {
		var jvhash = javaConstants.hashMessage;
		var jshash = CryptoJS.SHA256("Message");
		assert.assertEquals(jvhash, ""+jshash.toString(CryptoJS.enc.Latin1));
	}, 
	
	hashPaddingTest: function() {
	
		var jvbinaryString2f77668a9dfbf8d5 = javaConstants.binaryString2f77668a9dfbf8d5;
		var jvbinaryStringPadded2f77668a9dfbf8d5 = javaConstants.binaryStringPadded2f77668a9dfbf8d5;
		var jvhexStringPadded2f77668a9dfbf8d5 = javaConstants.hexStringPadded2f77668a9dfbf8d5;
		var jvhashPaddedOf2f77668a9dfbf8d5 = javaConstants.hashPaddedOf2f77668a9dfbf8d5;
		var jvhexHashPaddedOf2f77668a9dfbf8d5 = javaConstants.hexHashPaddedOf2f77668a9dfbf8d5;
		println("jvraw: "+jvbinaryString2f77668a9dfbf8d5);
		println("jvpad: "+jvbinaryStringPadded2f77668a9dfbf8d5);
		println("jv16 : "+jvhexStringPadded2f77668a9dfbf8d5);
		println("jvhsh: "+jvhashPaddedOf2f77668a9dfbf8d5);
		println("jvhex: "+jvhexHashPaddedOf2f77668a9dfbf8d5);
		
		var v2f77668a9dfbf8d5 = "2f77668a9dfbf8d5";
		var words = CryptoJS.enc.Hex.parse(v2f77668a9dfbf8d5);
		println("js16:  "+words);
		var jshsh = CryptoJS.SHA256(words);
		println("jshsh: "+jshsh);
		
		/*
		var jvhashPaddedOf2f77668a9dfbf8d5 = javaConstants.hashPaddedOf2f77668a9dfbf8d5;
		println("jvhash: "+jvhashPaddedOf2f77668a9dfbf8d5);

		var jvhashPaddedOf2f77668a9dfbf8d5_2 = javaConstants.hashPaddedOf2f77668a9dfbf8d5_2;
		println("jvhash2: "+jvhashPaddedOf2f77668a9dfbf8d5_2);

		var jshash = CryptoJS.SHA256(words);
		
		
		
		var words = CryptoJS.enc.Hex.parse(v2f77668a9dfbf8d5);
		println("words.words: "+ (typeof words.words));

// INDIVIDUAL 32bit words look negative but the engine ignores that
// IT HAS CLONE AND SIGBYTES AND CLAMP WHICH SHOULD ALLOW TO HASH PAD
// MANIPULATE THE BUFFERS MUCH LIKE THE JAVA CODE. 

		for( var i = 0; i < words.words.length; i++ ) {
			var w = words.words[i];
			println(i+":"+w.toString(2));
		}

		println("words: "+words.toString());
		*/
	}

	/*
	hashingTest: function() {
	
		var jvString = javaConstants.testString;
		var jsString = "7B72632B71CD83BD8CA419291CFA11039237EFF78CF18A30AE20195D68395A61DFBEA5752221CF18EBC743D6B6138963600F9D960422F429994336A7C87305FCF8E555197343A81D53BF029245B8CDCF18EEDC812ABB5792A1EAE3BDE1C87DE9A6A602EE24C0C5ED9071AB53A3E024606772BD3FB1E1C26394F5948E25ADEAEC";

		assert.assertEquals(jvString, jsString); 
		
		var jvBytes = javaConstants.testBytes;
		var jsBytes = moduleSHA256.hex2bytes(jsString);
		
		var jvBytesLength = jvBytes.length;
		var jsBytesLength = jsBytes.length;
		
		jsAssert.assertIntegerEquals(jvBytesLength, jsBytesLength);
		
		for( var i = 0; i < jvBytes.length; i++ ) {
			var jvb = jvBytes[i];
			var jsb = jsBytes[i];
			jsAssert.assertIntegerEquals(jvb, jsb);
		}

		var jvHashA = javaConstants.hashA;
		var jvA = javaConstants.paddedA;
		
		println("jvA.length:     "+jvA.length);
		println("jvHashA.length: "+jvHashA.length);
		
		var jsHashA = moduleSHA256.hashBinaryArray(jvA);
		
		var jvHashLength = jvHashA.length;
		var jsHashLength = jsHashA.length;
		
		//println((8*jvHashLength)+ " " + (8*jsHashLength));
		
		jsAssert.assertIntegerEquals(jvHashLength, jsHashLength);
		for( var i = 0; i < jvHashA.length; i++ ) {
			var jvb = jvHashA[i];
			var jsb = jsHashA[i];
			println(jvb+" "+jsb);
			//jsAssert.assertIntegerEquals(jvb, jsb);
		}
	}
	*/
});
