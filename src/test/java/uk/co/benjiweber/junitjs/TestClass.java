package uk.co.benjiweber.junitjs;

import java.util.List;

public class TestClass {
	public final List<TestCase> testCases;
	public final String name;

	public TestClass(String name, List<TestCase> testCases) {
		this.testCases = testCases;
		this.name = name;
	}
	
}
