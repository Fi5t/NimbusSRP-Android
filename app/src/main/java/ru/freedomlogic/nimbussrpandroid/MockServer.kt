package ru.freedomlogic.nimbussrpandroid

import com.nimbusds.srp6.SRP6CryptoParams
import com.nimbusds.srp6.SRP6ServerSession
import com.nimbusds.srp6.SRP6VerifierGenerator
import java.math.BigInteger


object MockServer {
    private const val SALT_LENGTH_BYTE = 32

    private const val USER_ACCOUNT_LOGIN = "admin"
    private const val USER_ACCOUNT_PASSWORD = "admin"

    private val defaultCryptoParams by lazy {
        SRP6CryptoParams(
                SRP6CryptoParams.N_2048,
                BigInteger(byteArrayOf(2)),
                "SHA-256"
        )
    }

    private val verifierGenerator = SRP6VerifierGenerator(defaultCryptoParams)
    private var serverSession = SRP6ServerSession(defaultCryptoParams)


    fun step1(login: String): Pair<BigInteger, BigInteger> {
        val salt = verifierGenerator.generateRandomSalt(SALT_LENGTH_BYTE)

        val verifier = verifierGenerator.generateVerifier(
                salt,
                USER_ACCOUNT_LOGIN.toByteArray(),
                USER_ACCOUNT_PASSWORD.toByteArray()
        )

        val bSalt = salt.map { String.format("%02x", it) }
                .reduce { acc, s -> "$acc$s" }
                .toBigInteger(16)

        val bValue = serverSession.step1(login, bSalt, verifier)

        return Pair(bSalt, bValue)
    }

    fun step2(A: BigInteger, M1: BigInteger): BigInteger {
        return serverSession.step2(A, M1)
    }

    fun reset() {
        serverSession = SRP6ServerSession(defaultCryptoParams)
    }
}