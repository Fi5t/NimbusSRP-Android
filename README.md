
![NimbusSRP](https://bytebucket.org/connect2id/nimbus-srp/raw/0d77bbb18b5e223115135b6582ef6998596abd42/nimubs-logo-small.png)

[![Quality Gate](https://sonarqube.com/api/badges/gate?key=com.nimbusds%3Asrp6a)](https://sonarqube.com/dashboard/index/com.nimbusds%3Asrp6a)

#### This project is analysed on [SonarQube.com](https://sonarqube.com)!


Nimbus SRP: Secure Remote Password (SRP-6a) protocol implementation for Java

Copyright (c) Connect2id Ltd. and others, 2011 - 2016

README

This package provides a complete Secure Remote Password (SRP-6a) implementation 
for Java.

Features:

	* Convenient client and server-side session classes, with tracking of the
	  current authentication state.
	  
	* Convenient verifier 'v' generator.
	
	* Allows selection of preferred 'N' and 'g' crypto parameters, hash 
	  function 'H' and session timeouts.
	  
	* Includes a set of pre-computed safe primes 'N' of various bitsizes 
	  (256-bit, 512-bit, etc.)
	  
	* Interfaces to allow definition of custom routines for the password key
	  'x', the hash routine, the server evidence message 'M1' and the client
	  evidence message 'M2'.

	* No external package dependencies. 


This product uses the 'Secure Remote Password' cryptographic authentication 
system developed by Tom Wu (tjw@CS.Stanford.EDU).

For installation instructions, usage and other information visit the Nimbus SRP
website:

	http://connect2id.com/products/nimbus-srp

Content of this package:

	README.txt                This file.
	
	LICENSE.txt               The Apache 2.0 software license.
	
	nimbus-srp-<version>.jar  JAR file containing the library classes.
	
	srp-client.jar            Interactive command-line client and verifier 
	                          generator for Secure Remote Password (SRP-6a)
	                          authentication.
	
	srp-server.jar            Interactive command-line server for Secure 
	                          Remote Password (SRP-6a) authentication.
	
	pom.xml                   Apache Maven build file.
	
	src/                      The source code.


Change log:

version 1.0 (2011-10-31)
	* First release.

version 1.1 (2011-11-09)
	* Adds a convenient verifier 'v' generator class.
	* Adds interfaces to allow definition of custom routines for the 
	  password key 'x', the server evidence message 'M1' and the client 
	  evidence message 'M2'.

version 1.2 (2011-11-18)
	* Enables storage of arbitrary SRP-6a auth session attributes.
	* Adds session 'A', 'B', 'M1' and 'M2' getter methods.

version 1.3 (2011-11-28)
	* Adds command-line SRP-6a verifier generator, server and client.

version 1.4 (2012-07-30)
	* Removes unused lookUpHexAlphabet field and LOOKUPLENGTH constant.
	* Fixes SRP6Session.hasTimedOut() bug.

version 1.4.1 (2013-04-05)
	* Switches build to Apache Maven.
	* Publishes library to Maven Central.

version 1.5 (2014-06-10)
	* Adds interface for custom computeU routine.
	* Refactors BigInteger utility class.
	* Switches project license to Apache 2.0.

version 1.5.1 (2014-08-15)
    * Introduces stricter 'g' parameter checking.
    * Adds precomputed 1536 and 2048-bit 'N' parameters from RFC 5054, Appendix
      A.

version 1.5.2 (2014-12-22)
	* Adds missing URoutine support to client session (iss #9).
	* Fixes BigInteger to byte array conversion in SRP6VerifierGenerator (iss
	  #10).

version 1.5.3 (2015-06-03)
	* Makes SRP6Session serialisable (iss #3).

version 2.0.0 (2016-10-27) 
	* Consistent use of RFC2945 conversions between byte array and BigInteger (iss #11, 
	#12, #13) by Jonathan Haas. 
	* Changed method signature of getSessionKey (now two methods not one with a switch)
	* Depending on how you are generating your random salt, and whether it is an RFC2945 
	legal byte string, you may lock your users out upgrading from older version. 
	It is best to assume all users will have to reset their verifier if upgrading from a 
	previous version.
 
[EOF]