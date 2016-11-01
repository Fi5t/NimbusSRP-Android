package com.nimbusds.srp6.cli;

import junit.framework.TestCase;
import org.junit.Before;

import java.io.IOException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

public class SRP6ToolsTest extends TestCase {

    class TestableSRP6Client extends SRP6Client {

        List<String> clientInput = new ArrayList<>();
        List<String> clientOutput = new ArrayList<>();

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
            clientOutput.add(msg);
        }
    }

    class TestableSRP6Server extends SRP6Server {
        TestableSRP6Server() throws IOException {
        }

        List<String> serverInput = new ArrayList<>();
        List<String> serverOutput = new ArrayList<>();

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
            serverOutput.add(msg);
        }
    }

    public void testOneRoundTrip() throws Exception {

        final SecureRandom notRandomAtAll = new SecureRandom(){
            byte b = Integer.valueOf(0xff).byteValue();

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
                // config
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
                System.out.println(msg);
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

        assertEquals("ffffffffffffffffffffffffffffffff", salt.get());
        assertEquals("34859b915801c7040a2bf0ae96d40aef87fcd1be53906061b02dc9ea0943a563", verifier.get());

        final AtomicReference<String> B = new AtomicReference<>();
        final AtomicReference<String> M2 = new AtomicReference<>();
        final AtomicReference<String> S = new AtomicReference<>();
        final AtomicReference<String> Shash = new AtomicReference<>();

        SRP6Server server = new TestableSRP6Server() {
            {
                // config
                serverInput.add("1");
                serverInput.add("SHA-1");
                serverInput.add("tom@arcot.com");
                // salt + veriifer
                serverInput.add("ffffffffffffffffffffffffffffffff");
                serverInput.add("34859b915801c7040a2bf0ae96d40aef87fcd1be53906061b02dc9ea0943a563");
                // A + M1
                serverInput.add("1c4ab1a68975a8e1e07424e67090330cd9112705eb70dccdcb9a5f2052aa4488");
                serverInput.add("236fbca54da7f52843baf872b1749515eed10a7c"); // ???
                random = notRandomAtAll;
            }

            @Override
            protected void println(String msg) {
                System.out.println(msg);
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
                S.set(SS);
            }
        };

//        server.run();
//        assertEquals("7f4ca6fe958d4ef729f79c56b39a7ee738e43ea733b19e783db4ce47fe028765", B.get());
//        assertEquals("220eba14444e38e8a09da4164391dfaec897d0d7fcd5595f7c9a4ae1aafbc06a", S.get());
//        assertEquals("-", M2.get());

        final AtomicReference<String> A = new AtomicReference<>();
        final AtomicReference<String> M1 = new AtomicReference<>();

        SRP6Client client = new TestableSRP6Client() {
            {
                // config
                clientInput.add("2");
                clientInput.add("tom@arcot.com");
                clientInput.add("some|complex?password!");
                clientInput.add("1");
                clientInput.add("SHA-1");
                // salt
                clientInput.add("85e220dc7b5a858a0fddbe508d960927");
                // B + M2
                clientInput.add("7f4ca6fe958d4ef729f79c56b39a7ee738e43ea733b19e783db4ce47fe028765");
                clientInput.add("ff");
                random = notRandomAtAll;
            }

            @Override
            protected void println(String msg) {
                System.out.println(msg);
            }

            @Override
            void logA(String AA) {
                A.set(AA);
            }

            @Override
            void logM1(String MM1) {
                M1.set(MM1);
            }
        };

        client.run();
        assertEquals("1c4ab1a68975a8e1e07424e67090330cd9112705eb70dccdcb9a5f2052aa4488", A);
        assertEquals("236fbca54da7f52843baf872b1749515eed10a7c", M1);


    }
}
