Nimbus SRP : Secure Remote Password (SRP-6a) protocol implementation for Java. 

Copyright (c) Vladimir Dzhuvinov, 2011 - 2012


README

This package provides a complete Secure Remote Password (SRP-6a) implementation 
for Java.

Features:

	* Convenient client and server-side session classes, with tracking of 
	  the current authentication state.
	  
	* Convenient verifier 'v' generator.
	
	* Allows selection of preferred 'N' and 'g' crypto parameters, hash 
	  function 'H' and session timeouts.
	  
	* Includes a set of pre-computed safe primes 'N' of various bitsizes 
	  (256-bit, 512-bit, etc.)
	  
	* Interfaces to allow definition of custom routines for the password 
	  key 'x', the server evidence message 'M1' and the client evidence 
	  message 'M2'.

	* No external package dependencies. 


This product uses the 'Secure Remote Password' cryptographic authentication 
system developed by Tom Wu (tjw@CS.Stanford.EDU).

For installation instructions, usage and other information visit the Nimbus SRP
website:

	http://software.dzhuvinov.com/nimbus-srp.html
	

Content of this package:

	README.txt                This file.
	
	LICENSE-Commercial.txt    The commercial software license.
	
	LICENSE-GPL.txt           The GPL 2.0 software license.
	
	nimbus-srp-<version>.jar  JAR file containing the library classes.
	
	srp-client.jar            Interactive command-line client and verifier 
	                          generator for Secure Remote Password (SRP-6a) 
				  authentication.
	
	srp-server.jar            Interactive command-line server for Secure 
	                          Remote Password (SRP-6a) authentication.
	
	build.xml                 Apache Ant build file.
	
	javadoc/                  JavaDoc files.
	
	lib/                      Build and test dependencies.
	
	src/                      The source code.
	
	test/                     JUnit tests.


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
	* 
	* 

[EOF]
