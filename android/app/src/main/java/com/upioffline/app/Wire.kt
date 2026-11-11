package com.upioffline.app

import com.upioffline.protocol.Envelope
import org.json.JSONObject
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.InputStream
import java.io.OutputStream
import java.util.UUID

/** Bluetooth framing (4-byte length + JSON) and the Envelope's JSON form, which matches the backend API. */
object Wire {
    const val MAX_FRAME = 16 * 1024
    const val ACK = 0x06

    fun writeFrame(out: OutputStream, bytes: ByteArray) {
        require(bytes.size in 1..MAX_FRAME) { "packet too large" }
        DataOutputStream(out).run { writeInt(bytes.size); write(bytes); flush() }
    }

    fun readFrame(input: InputStream): ByteArray {
        val data = DataInputStream(input)
        val size = data.readInt()
        require(size in 1..MAX_FRAME) { "bad frame size $size" }
        return ByteArray(size).also { data.readFully(it) }
    }

    fun toJson(e: Envelope): String = JSONObject()
        .put("protocolVersion", e.protocolVersion)
        .put("transactionId", e.transactionId)
        .put("senderId", e.senderId)
        .put("receiverId", e.receiverId)
        .put("nonce", e.nonce)
        .put("encryptedKey", e.encryptedKey)
        .put("ciphertext", e.ciphertext)
        .toString()

    /** Parses untrusted input from Bluetooth. The transaction id is checked because it becomes a filename. */
    fun fromJson(json: String): Envelope = JSONObject(json).run {
        val id = getString("transactionId")
        require(UUID.fromString(id).toString() == id) { "bad transactionId" }
        Envelope(
            getInt("protocolVersion"), id, getString("senderId"), getString("receiverId"),
            getString("nonce"), getString("encryptedKey"), getString("ciphertext")
        )
    }
}
