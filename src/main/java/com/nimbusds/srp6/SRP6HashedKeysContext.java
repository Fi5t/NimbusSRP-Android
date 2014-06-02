package com.nimbusds.srp6;

import java.math.BigInteger;

public class SRP6HashedKeysContext {

	public final BigInteger A;
	public final BigInteger B;

	public SRP6HashedKeysContext(BigInteger A, BigInteger B) {
		this.A = A;
		this.B = B;
	}

}
