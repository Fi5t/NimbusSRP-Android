// Copyright 2013 Benji Weber http://benjiweber.co.uk/blog/2013/01/27/javascript-tests-with-junit/
var assert = Packages.org.junit.Assert;
var jsAssert = {};
var TestCase = Packages.uk.co.benjiweber.junitjs.TestCase;

if (typeof println == 'undefined') this.println = print;

jsAssert.assertIntegerEquals = function(a, b) {
	if (a === b) return;
	throw new Packages.org.junit.ComparisonFailure("Expected <" + a + "> but was <" + b + ">", a, b);
}

var nashornDetector = {
	__noSuchMethod__:  function(name, arg0, arg1) {
		return typeof arg1 != "undefined";
	}
}

var isRhino = function() {
	return !nashornDetector.detect('one','two');
}

var console = {
	log: function(text) {
		print(text + (isRhino() ? "\n" : ""));
	}
}

var newStub = function() {
	return 	{
		called: [],
		__noSuchMethod__:  function(name, arg0, arg1, arg2, arg3, arg4, arg5) {
			var desc = {
				name: name,
				args: []
			};
			var rhino = arg0.length && typeof arg1 == "undefined";
			
			var args = rhino ? arg0 : arguments;
			for (var i = rhino ? 0 : 1; i < args.length; i++){
				if (typeof args[i] == "undefined") continue;
				desc.args.push(args[i]);
			}
			this.called.push(desc);
		},
		
		assertCalled: function(description) {
			
			var fnDescToString = function(desc) {
				return desc.name + "("+ desc.args.join(",") +")";
			};
			
			if (this.called.length < 1) assert.fail('No functions called, expected: ' + fnDescToString(description));

			for (var i = 0; i < this.called.length; i++) {
				var fn = this.called[i];
				if (fn.name == description.name) {
					if (description.args.length != fn.args.length) continue;
					
					for (var j = 0; j < description.args.length; j++) {
						if (fn.args[j] == description.args[j]) return;
					}
				}
			}
			
			assert.fail('No matching functions called. expected: ' + 
					'<' + fnDescToString(description) + ")>" +
					' but had ' +
					'<' + this.called.map(fnDescToString).join("|") + '>'
			);
		}
	};
};

var tests = function(testObject) {
	var testCases = new java.util.ArrayList();
	for (var name in testObject) {
		if (testObject.hasOwnProperty(name)) {
			testCases.add(new TestCase(name,testObject[name]));
		}
	}
	return testCases;
};
