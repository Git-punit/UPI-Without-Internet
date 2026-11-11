package com.upioffline.app

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.PublicKey

/** The sender's signing key. Lives in Android Keystore and never leaves the device. */
object DeviceKeys {
    private const val ALIAS = "upi-offline-signing"

    fun publicKey(): PublicKey = entry().certificate.publicKey
    fun privateKey(): PrivateKey = entry().privateKey

    @Synchronized
    private fun entry(): KeyStore.PrivateKeyEntry {
        val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        if (!ks.containsAlias(ALIAS)) {
            val gen = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_RSA, "AndroidKeyStore")
            gen.initialize(
                KeyGenParameterSpec.Builder(ALIAS, KeyProperties.PURPOSE_SIGN)
                    .setKeySize(2048)
                    .setDigests(KeyProperties.DIGEST_SHA256)
                    .setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PSS)
                    .build()
            )
            gen.generateKeyPair()
        }
        return ks.getEntry(ALIAS, null) as KeyStore.PrivateKeyEntry
    }
}
