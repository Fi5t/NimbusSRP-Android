package ru.freedomlogic.nimbussrpandroid

import android.os.Bundle
import android.support.v7.app.AppCompatActivity
import com.nimbusds.srp6.SRP6ClientCredentials
import com.nimbusds.srp6.SRP6ClientSession
import com.nimbusds.srp6.SRP6CryptoParams
import kotlinx.android.synthetic.main.activity_main.*
import java.math.BigInteger

class MainActivity : AppCompatActivity() {

    private val defaultCryptoParams by lazy {
        SRP6CryptoParams(
                SRP6CryptoParams.N_2048,
                BigInteger(byteArrayOf(2)),
                "SHA-256"
        )
    }

    private var clientSession = SRP6ClientSession()

    private lateinit var clientCredentials: SRP6ClientCredentials

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        button.setOnClickListener {
            val login = editTextLogin.text.toString()
            val password = editTextPassword.text.toString()

            val (salt, B) = MockServer.step1(login)

            clientCredentials = with(clientSession) {
                step1(login, password)
                step2(defaultCryptoParams, salt, B)
            }

            val M2 = with(clientCredentials) {
                MockServer.step2(A, M1)
            }

            clientSession.step3(M2)

            reset()

            editTextSalt.setText("Salt: $salt")
            editTextB.setText("B: $B")
            editTextA.setText("A: ${clientCredentials.A}")
            editTextM1.setText("M1: ${clientCredentials.M1}")
            editTextM2.setText("M2: $M2")
        }
    }

    private fun reset() {
        MockServer.reset()
        clientSession = SRP6ClientSession()
    }
}
