package com.nimbusds.srp6.cli;

import com.nimbusds.srp6.*;
import junit.framework.TestCase;

import java.io.IOException;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;
import static javax.xml.bind.DatatypeConverter.*;

public class SRP6ToolsTest extends TestCase {

    class TestableSRP6Client extends SRP6Client {

        List<String> clientInput = new ArrayList<>();

        int counter = 0;

        TestableSRP6Client() throws IOException {
        }

        @Override
        public String readInput(String def) throws IOException {
            return clientInput.get(counter++);
        }

        @Override
        public String readInput() throws IOException {
            return clientInput.get(counter++);
        }

        @Override
        protected void println() {
            // do nothing
        }

        @Override
        protected void println(String msg) {
            // do nothing
        }
    }

    class TestableSRP6Server extends SRP6Server {
        TestableSRP6Server() throws IOException {
        }

        List<String> serverInput = new ArrayList<>();

        int counter = 0;

        @Override
        public String readInput(String def) throws IOException {
            return serverInput.get(counter++);
        }

        @Override
        public String readInput() throws IOException {
            return serverInput.get(counter++);
        }

        @Override
        protected void println() {
            // do nothing
        }

        @Override
        protected void println(String msg) {
            // do nothing
        }
    }

    public void testRandomInteractionManyOnesSalt() throws Exception {
        final SecureRandom notRandomAtAll = new SecureRandom(){
            byte b = Integer.valueOf(0x1).byteValue();

            @Override
            public synchronized void nextBytes(byte[] bytes) {
                for( int i = 0; i < bytes.length; i++ ){
                    bytes[i] = b;
                }
            }
        };
        testInteraction(notRandomAtAll);
    }

    public void testRandomInteractionOnesSalt() throws Exception {
        final SecureRandom notRandomAtAll = new SecureRandom(){
            byte b = Integer.valueOf(0xff).byteValue();

            @Override
            public synchronized void nextBytes(byte[] bytes) {
                for( int i = 0; i < bytes.length; i++ ){
                    bytes[i] = b;
                }
            }
        };
        testInteraction(notRandomAtAll);
    }

    void testInteraction(final SecureRandom notRandomAtAll) throws Exception {

        SRP6CryptoParams config = SRP6CryptoParams.getInstance(256, "SHA-1");

        SRP6VerifierGenerator vGen = new SRP6VerifierGenerator(config);

        byte[] zeros = vGen.generateRandomSalt(16, notRandomAtAll);

        SRP6Client.User user = new SRP6Client.User("tom@arcot.com", "some|complex?password!");

        BigInteger s = BigIntegerUtils.bigIntegerFromBytes(zeros);

        BigInteger v = vGen.generateVerifier(s, user.I, user.P);

        SRP6ServerSession server = new SRP6ServerSession(config){{
            /**
             * this override is so that JUnit tests ccan inject a not-so-random generator from the outside.
             * you can just use a vanilla SRP6ServerSession which initialises its own secure random.
             */
            this.random = notRandomAtAll;
        }};

        BigInteger B = server.step1(user.I, s, v);

        SRP6ClientSession client = new SRP6ClientSession(){{
            /**
             * this override is so that JUnit tests ccan inject a not-so-random insecure generator from the outside.
             * to be secure simply use SRP6ClientSession without overriding its random generator.
             */
            this.random = notRandomAtAll;
        }};

        client.step1(user.I, user.P);

        SRP6ClientCredentials cred = client.step2(config, s, B);

        BigInteger M2 = server.step2(cred.A, cred.M1);

        client.step3(M2);

        BigInteger serverKey = server.getSessionKey();
        BigInteger clientKey = client.getSessionKey();

        assertEquals(serverKey, clientKey);

        byte[] serverHash = server.getSessionKeyHash();
        byte[] clientHash = client.getSessionKeyHash();

        assertTrue(Arrays.equals(serverHash, clientHash));
    }

    public void testOneRoundTripCli() throws Exception {
        final SecureRandom notRandomAtAll = new SecureRandom(){
            byte b = Integer.valueOf(0x1).byteValue();

            @Override
            public synchronized void nextBytes(byte[] bytes) {
                for( int i = 0; i < bytes.length; i++ ){
                    bytes[i] = b;
                }
            }
        };

        final AtomicReference<String> salt = new AtomicReference<>();
        final AtomicReference<String> verifier = new AtomicReference<>();

        SRP6Client clientVerifier = new TestableSRP6Client() {
            {
                clientInput.add("1");
                clientInput.add("1");
                clientInput.add("SHA-1");
                clientInput.add("tom@arcot.com");
                clientInput.add("some|complex?password!");
                clientInput.add("16");
                random = notRandomAtAll;
            }

            @Override
            protected void println(String msg) {
                // do nothing
            }

            @Override
            protected void print(String s) {
                // do nothing
            }

            @Override
            protected void logV(String V) {
                verifier.set(V);
            }

            @Override
            protected void logSalt(String s) {
                salt.set(s);
            }

        };

        clientVerifier.run();

        assertEquals("1010101010101010101010101010101", salt.get());
        assertEquals("106bfe2b6d1a1ee611b0ededd8d2a70ca3cb7222c7304aba4cca0688644de7f9d", verifier.get());

        final AtomicReference<String> A = new AtomicReference<>();
        final AtomicReference<String> M1 = new AtomicReference<>();
        final AtomicReference<String> SS = new AtomicReference<>();
        final AtomicReference<String> SShash = new AtomicReference<>();

        SRP6Client client = new TestableSRP6Client() {
            {
                // config
                clientInput.add("2");
                clientInput.add("tom@arcot.com");
                clientInput.add("some|complex?password!");
                clientInput.add("1");
                clientInput.add("SHA-1");
                // salt
                clientInput.add("1010101010101010101010101010101");
                // B + M2
                clientInput.add("ed438c1e83dd9a1136118f40d479c2c289488f5d23bef7f7d3d9845def70875d");
                clientInput.add("3da965a589207c91057ff3ee5e1df0e044e3ce51");
                random = notRandomAtAll;
            }

            @Override
            protected void println(String msg) {
                // do nothing
            }
            @Override
            protected void print(String msg) {
                // do nothing
            }

            @Override
            void logA(String AA) {
                A.set(AA);
            }

            @Override
            void logM1(String MM1) {
                M1.set(MM1);
            }

            @Override
            void logS(String S) {
                SS.set(S);
            }

            @Override
            void logShash(byte[] sessionKeyHash) {
                SShash.set(printHexBinary(sessionKeyHash));
            }
        };

        client.run();
        assertEquals("551c146ce655a278e57f8583856795b458591e5a037b8c4758bd6b5351cab975", A.get());
        assertEquals("96ef9cb9a648e92886e7c904d464f21169dbaab4", M1.get());
        assertEquals("d61a84d1d442ff620f4a8baf8adc36c348376e92cc290f8981e46e6ead783ae4", SS.get());

        final AtomicReference<String> B = new AtomicReference<>();
        final AtomicReference<String> M2 = new AtomicReference<>();
        final AtomicReference<String> SC = new AtomicReference<>();
        final AtomicReference<String> SChash = new AtomicReference<>();

        SRP6Server server = new TestableSRP6Server() {
            {
                // config
                serverInput.add("1");
                serverInput.add("SHA-1");
                serverInput.add("tom@arcot.com");
                // salt + veriifer
                serverInput.add("1010101010101010101010101010101");
                serverInput.add("106bfe2b6d1a1ee611b0ededd8d2a70ca3cb7222c7304aba4cca0688644de7f9d");
                // A + M1
                serverInput.add("551c146ce655a278e57f8583856795b458591e5a037b8c4758bd6b5351cab975");
                serverInput.add("96ef9cb9a648e92886e7c904d464f21169dbaab4");
                random = notRandomAtAll;
            }

            @Override
            protected void println(String msg) {
                // do nothing
            }

            @Override
            protected void print(String s) {
                // do nothing
            }

            @Override
            void logB(String BB) {
                B.set(BB);
            }

            @Override
            void logM2(String MM2) {
               M2.set(MM2);
            }

            @Override
            void logS(String SS) {
                SC.set(SS);
            }

            @Override
            void logShash(byte[] sessionKeyHash) {
                SChash.set(printHexBinary(sessionKeyHash));
            }
        };

        server.run();
        assertEquals("ed438c1e83dd9a1136118f40d479c2c289488f5d23bef7f7d3d9845def70875d", B.get());
        assertEquals("d61a84d1d442ff620f4a8baf8adc36c348376e92cc290f8981e46e6ead783ae4", SC.get());
        assertEquals("3da965a589207c91057ff3ee5e1df0e044e3ce51", M2.get());

        assertEquals(SChash.get(), SShash.get());
    }
}
