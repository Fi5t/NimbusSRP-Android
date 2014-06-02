// Copyright 2013 Benji Weber http://benjiweber.co.uk/blog/2013/01/27/javascript-tests-with-junit/
package uk.co.benjiweber.junitjs;

import static java.lang.annotation.RetentionPolicy.RUNTIME;

import java.lang.annotation.Retention;

@Retention(RUNTIME)
public @interface Tests {
	String[] value();
}
