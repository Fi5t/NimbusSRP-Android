package uk.co.benjiweber.junitjs;

import static java.lang.annotation.RetentionPolicy.RUNTIME;

import java.lang.annotation.Retention;

@Retention(RUNTIME)
public @interface Tests {
	String[] value();
}
