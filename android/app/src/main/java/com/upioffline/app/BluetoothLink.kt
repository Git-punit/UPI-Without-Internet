package com.upioffline.app

import android.annotation.SuppressLint
import android.bluetooth.BluetoothAdapter
import android.bluetooth.BluetoothDevice
import android.bluetooth.BluetoothServerSocket
import java.io.IOException
import java.util.UUID
import kotlin.concurrent.thread

// shortcut: RFCOMM to already-paired devices only (pair in system Bluetooth settings first); add discovery if pairing is too clunky.
// Secure RFCOMM: the link is encrypted and authenticated by pairing, on top of the packet's own encryption.
val SERVICE_UUID: UUID = UUID.fromString("7d3c2f8e-5b1a-4c6e-9f0d-2a8b4e6c1d3f")

/** Sends one packet and waits for the receiver's ACK, which means "stored", never "paid". Blocking. */
@SuppressLint("MissingPermission") // MainActivity checks BLUETOOTH_CONNECT first
fun sendPacket(device: BluetoothDevice, packet: ByteArray) {
    device.createRfcommSocketToServiceRecord(SERVICE_UUID).use { socket ->
        socket.connect()
        Wire.writeFrame(socket.outputStream, packet)
        check(socket.inputStream.read() == Wire.ACK) { "receiver did not acknowledge" }
    }
}

/** Accepts packets until stopped. [onPacket] must persist the packet or throw; only then is an ACK sent. */
class BluetoothReceiver(
    private val adapter: BluetoothAdapter,
    private val onPacket: (ByteArray) -> Unit,
    private val onError: (Exception) -> Unit,
) {
    @Volatile private var server: BluetoothServerSocket? = null

    @SuppressLint("MissingPermission")
    fun start() {
        val s = adapter.listenUsingRfcommWithServiceRecord("UPI Offline", SERVICE_UUID)
        server = s
        thread(name = "bt-receiver") {
            while (true) {
                val socket = try { s.accept() } catch (e: IOException) { break } // closed by stop()
                try {
                    socket.use {
                        onPacket(Wire.readFrame(it.inputStream))
                        it.outputStream.write(Wire.ACK)
                        it.outputStream.flush()
                        it.inputStream.read() // let the sender read the ACK and close first
                    }
                } catch (e: Exception) {
                    onError(e)
                }
            }
        }
    }

    fun stop() {
        server?.close()
        server = null
    }

    val running get() = server != null
}
