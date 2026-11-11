package com.upioffline.app

import com.upioffline.protocol.Envelope
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.DataOutputStream

class WireTest {

    private val env = Envelope(1, "a9b2f88d-8b5a-4d6d-bdf1-3a87f39bfc71", "alice", "bob", "bm9uY2U=", "a2V5", "Y3Q=")

    @Test
    fun frameRoundTrip() {
        val out = ByteArrayOutputStream()
        Wire.writeFrame(out, "hello".toByteArray())
        assertArrayEquals("hello".toByteArray(), Wire.readFrame(ByteArrayInputStream(out.toByteArray())))
    }

    @Test
    fun oversizedFrameRejectedBeforeAllocating() {
        val out = ByteArrayOutputStream()
        DataOutputStream(out).writeInt(Int.MAX_VALUE)
        assertThrows(IllegalArgumentException::class.java) { Wire.readFrame(ByteArrayInputStream(out.toByteArray())) }
    }

    @Test
    fun envelopeJsonRoundTrip() {
        assertEquals(env, Wire.fromJson(Wire.toJson(env)))
    }

    @Test
    fun pathTraversalTransactionIdRejected() {
        val bad = Wire.toJson(env).replace(env.transactionId, "../../shared_prefs/x")
        assertThrows(IllegalArgumentException::class.java) { Wire.fromJson(bad) }
    }
}
