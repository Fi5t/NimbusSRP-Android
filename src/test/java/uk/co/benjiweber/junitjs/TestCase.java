// Copyright 2013 Benji Weber http://benjiweber.co.uk/blog/2013/01/27/javascript-tests-with-junit/
package uk.co.benjiweber.junitjs;


public class TestCase {

	public final String name;
	public final Runnable testCase;

	public TestCase(String name, Runnable testCase) {
		this.name = name;
		this.testCase = testCase;
	}
}
