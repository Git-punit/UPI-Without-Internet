package com.upioffline.app

import com.upioffline.protocol.Envelope
import org.json.JSONObject
import java.io.File

/**
 * One file per packet in app-private storage, so packets survive restarts and disconnections.
 * The contents are already encrypted to the backend, so files hold no readable amounts.
 */
// shortcut: plain files instead of Room; move to a database if you need queries or many packets.
class PacketStore(private val dir: File) {
    data class Stored(val envelope: Envelope, val status: String)

    init {
        dir.mkdirs()
    }

    @Synchronized
    fun save(envelope: Envelope, status: String) {
        val json = JSONObject().put("envelope", Wire.toJson(envelope)).put("status", status).toString()
        val tmp = File(dir, envelope.transactionId + ".tmp")
        tmp.writeText(json)
        check(tmp.renameTo(File(dir, envelope.transactionId + ".json"))) { "could not save packet" }
    }

    @Synchronized
    fun contains(transactionId: String) = File(dir, "$transactionId.json").exists()

    @Synchronized
    fun all(): List<Stored> = (dir.listFiles { f -> f.name.endsWith(".json") } ?: emptyArray())
        .sortedBy { it.lastModified() }
        .map { f -> JSONObject(f.readText()).let { Stored(Wire.fromJson(it.getString("envelope")), it.getString("status")) } }
}
