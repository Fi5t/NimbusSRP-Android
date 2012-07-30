/**
 * Secure Remote Password (SRP-6a) protocol implementation.
 *
 * <p>Features:
 *
 * <ul>
 *     <li>Convenient client and server-side session classes, with tracking of 
 *         the current authentication state.
 *     <li>Convenient verifier 'v' generator.
 *     <li>Allows selection of preferred 'N' and 'g' crypto parameters, hash 
 *         function 'H' and session timeouts.
 *     <li>Includes a set of pre-computed safe primes 'N' of various bitsizes
 *         (256-bit, 512-bit, etc.)
 *     <li>Interfaces to allow definition of custom routines for the password 
 *         key 'x', the server evidence message 'M1' and the client evidence 
 *         message 'M2'.
 *     <li>No external package dependencies.
 * </ul>
 *
 * <p>The routines for computing the various SRP-6a variables and messages are 
 * described in {@link com.nimbusds.srp6.SRP6Routines}.
 *
 * <p>This product uses the 'Secure Remote Password' cryptographic 
 * authentication system developed by Tom Wu (tjw@CS.Stanford.EDU).
 *
 * @author <a href="http://dzhuvinov.com">Vladimir Dzhuvinov</a>
 * @version $version$ ($version-date$)
 */
package com.nimbusds.srp6;
