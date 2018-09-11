package com.nimbusds.srp6;

import junit.framework.TestCase;

import java.math.BigInteger;
import java.security.SecureRandom;

public class RandomNumberTest extends TestCase {

    public void testRandoms() {
        final SRP6Routines srp6Routines = new SRP6Routines();

        final SecureRandom secureRandom = new SecureRandom();

        final BigInteger N = new BigInteger("2").pow(512);

        for( int i = 0; i < 1e5; i++){
            BigInteger r = srp6Routines.generatePrivateValue(N, secureRandom);
            if( BigInteger.ZERO.compareTo(r) >= 0 ) fail("bad r<=0:"+r);
            if( r.compareTo(N) >= 0 ) fail("bad r>=N"+r);
        }

    }
}
