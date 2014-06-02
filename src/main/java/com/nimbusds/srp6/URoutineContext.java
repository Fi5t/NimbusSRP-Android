package com.nimbusds.srp6;

import java.math.BigInteger;

public class URoutineContext {

	public final BigInteger A;
	public final BigInteger B;

	public URoutineContext(BigInteger A, BigInteger B) {
		this.A = A;
		this.B = B;
	}

}
