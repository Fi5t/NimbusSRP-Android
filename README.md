# NimbusSRP-Android
 [ ![Download](https://api.bintray.com/packages/fi5t/security/srp6a-android/images/download.svg) ](https://bintray.com/fi5t/security/srp6a-android/_latestVersion)
[![GitHub license](https://img.shields.io/github/license/Fi5t/NimbusSRP-Android.svg)](https://github.com/Fi5t/NimbusSRP-Android/blob/master/LICENSE)


This is classic NimbusSRP library optimized for Android. If you are looking for Java version of this library refer to the [original repository](https://bitbucket.org/connect2id/nimbus-srp).

### Why?

When you using classical NimbusSRP with Android, you will definitely face java dependencies problem. I had to add `javax.xml.bind:jaxb-api` to my project just to provide normal NimbusSRP work. Moreover, not each version of `jaxb-api` works fine with Android (only 2.2.4 at this moment). Everything was almost fine until I decided to configure ProGuard with all this things. It was a really scary experience =) Finally, I decided to make alter version of NimbusSRP with Android in mind.

I didn't change the library code at all, just threw away unnecessary components from `cli` package.

### Usage

Add Gradle dependency to your project:
```groovy
implementation 'com.nimbusds:srp6a-android:2.0.2'
```

And write something like this:

```kotlin
clientCredentials = with(clientSession) {
    step1(login, password)
    step2(defaultCryptoParams, salt, B)
}

val M2 = with(clientCredentials) {
    MockServer.step2(A, M1)
}

clientSession.step3(M2)
```
[Go to full example](https://github.com/Fi5t/NimbusSRP-Android/blob/master/app/src/main/java/ru/freedomlogic/nimbussrpandroid/MainActivity.kt)

### What is NimbusSRP

This package provides a complete Secure Remote Password (SRP-6a) implementation for Java.

Features:

* Convenient client and server-side session classes, with tracking of the current authentication state.
* Convenient verifier 'v' generator.
* Allows selection of preferred 'N' and 'g' crypto parameters, hash function 'H' and session timeouts.
* Includes a set of pre-computed safe primes 'N' of various bitsizes (256-bit, 512-bit, etc.)
* Interfaces to allow definition of custom routines for the password key 'x', the hash routine, the server evidence message 'M1' and the client evidence message 'M2'.
* No external package dependencies.

This product uses the 'Secure Remote Password' cryptographic authentication system developed by Tom Wu (tjw@CS.Stanford.EDU).

For installation instructions, usage and more information visit the Nimbus SRP website:

[http://connect2id.com/products/nimbus-srp](http://connect2id.com/products/nimbus-srp)
