package com.upioffline.app

import android.Manifest
import android.app.Activity
import android.bluetooth.BluetoothDevice
import android.bluetooth.BluetoothManager
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import android.text.InputType
import android.view.View
import android.widget.*
import com.upioffline.protocol.EnvelopeCrypto
import com.upioffline.protocol.PaymentInstruction
import java.io.File
import java.io.IOException
import java.math.BigDecimal
import java.time.Duration
import java.util.Base64
import kotlin.concurrent.thread

/**
 * One app, both roles: a phone can send (offline) and receive/submit (online later).
 * Status words are chosen so a transfer is never mistaken for a payment.
 */
class MainActivity : Activity() {

    private val prefs by lazy { getSharedPreferences("upi-offline", MODE_PRIVATE) }
    private val sent by lazy { PacketStore(File(filesDir, "sent")) }
    private val inbox by lazy { PacketStore(File(filesDir, "inbox")) }
    // Mesh mode: packets for other people that this phone carries. Encrypted to the backend, so unreadable here.
    private val carried by lazy { PacketStore(File(filesDir, "carried")) }
    private val bluetooth get() = getSystemService(BluetoothManager::class.java).adapter

    private lateinit var urlField: EditText
    private lateinit var userField: EditText
    private lateinit var passField: EditText
    private lateinit var idField: EditText
    private lateinit var toField: EditText
    private lateinit var amountField: EditText
    private lateinit var deviceSpinner: Spinner
    private lateinit var receiveButton: Button
    private lateinit var inboxView: TextView
    private lateinit var logView: TextView
    private var pairedDevices: List<BluetoothDevice> = emptyList()
    private var receiver: BluetoothReceiver? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val root = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL; setPadding(40, 40, 40, 40) }

        root.heading("1. Set up (needs internet)")
        urlField = root.field("Backend URL", prefs.getString("url", "http://10.0.2.2:8081")!!)
        userField = root.field("Username", prefs.getString("user", "")!!)
        passField = root.field("Password (8+ characters)", "").apply {
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD
        }
        idField = root.field("This phone's device ID", prefs.getString("id", "")!!)
        root.button("Log in and register this phone") { register() }

        root.heading("2. Pay someone (works offline)")
        toField = root.field("Receiver's device ID", "")
        amountField = root.field("Amount in ₹", "").apply {
            inputType = InputType.TYPE_CLASS_NUMBER or InputType.TYPE_NUMBER_FLAG_DECIMAL
        }
        deviceSpinner = Spinner(this).also { root.addView(it) }
        root.button("Refresh paired phones") { refreshDevices() }
        root.button("Send payment request over Bluetooth") { send() }
        // Either side can submit: if the receiver never gets online, the sender's own copy still goes through.
        // Resubmitting is idempotent, so this is also how the sender learns the final outcome.
        root.button("Sync sent requests (online)") { sync(sent, "TRANSFERRED") }

        root.heading("3. Receive (offline), submit later (online)")
        receiveButton = root.button("Start receiving") { toggleReceiving() }
        root.button("Submit received requests (online)") { sync(inbox, "RECEIVED") }

        root.heading("4. Mesh: carry other people's payments")
        root.button("Forward carried packets to selected phone") { forwardCarried() }
        root.button("Upload carried packets (online)") { sync(carried, "CARRYING") }
        inboxView = TextView(this).also { root.addView(it) }

        root.heading("Log")
        logView = TextView(this).apply { setTextIsSelectable(true) }.also { root.addView(it) }

        setContentView(ScrollView(this).apply { addView(root) })
        refreshDevices()
        showInbox()
    }

    override fun onDestroy() {
        receiver?.stop()
        super.onDestroy()
    }

    /** Creates the account if needed, logs in, enrols this phone's Keystore key and caches the backend key. */
    private fun register() {
        val url = urlField.text.toString().trim()
        val user = userField.text.toString().trim()
        val password = passField.text.toString()
        val id = idField.text.toString().trim()
        if (!PaymentInstruction.isValidId(user)) return log("Username: 1–64 letters, digits, . _ -")
        if (!PaymentInstruction.isValidId(id)) return log("Device ID: 1–64 letters, digits, . _ -")
        background {
            val anon = BackendClient(url)
            try {
                anon.registerUser(user, password)
            } catch (e: BackendClient.HttpError) {
                if (e.error != "USERNAME_TAKEN") throw e // existing account: just log in
            }
            val token = anon.login(user, password)
            val client = BackendClient(url, token)
            val proof = Base64.getEncoder().encodeToString(
                EnvelopeCrypto.sign(EnvelopeCrypto.registrationMessage(id, user), DeviceKeys.privateKey()))
            try {
                client.registerDevice(id, EnvelopeCrypto.publicKeyToBase64(DeviceKeys.publicKey()), proof)
            } catch (e: BackendClient.HttpError) {
                if (e.error != "DEVICE_ID_TAKEN") throw e // re-login on an enrolled phone
            }
            // shortcut: token in plain SharedPreferences (app-private); use EncryptedSharedPreferences/Keystore for production.
            prefs.edit().putString("url", url).putString("user", user).putString("id", id)
                .putString("token", token).putString("backendKey", client.backendKey()).apply()
            runOnUiThread { passField.setText("") }
            "Logged in as $user, phone $id registered. You can now pay offline."
        }
    }

    private fun send() {
        if (!hasBluetoothPermission()) return
        val myId = prefs.getString("id", null) ?: return log("Register first")
        val backendKey = prefs.getString("backendKey", null) ?: return log("Register while online first")
        val device = pairedDevices.getOrNull(deviceSpinner.selectedItemPosition) ?: return log("Pick a paired phone")
        val to = toField.text.toString().trim()
        val amountMinor = try {
            BigDecimal(amountField.text.toString().trim()).movePointRight(2).longValueExact()
        } catch (e: RuntimeException) {
            return log("Amount must be like 250 or 250.50")
        }
        background {
            val ins = PaymentInstruction.create(myId, to, amountMinor, "INR", Duration.ofHours(12))
            val env = EnvelopeCrypto.seal(ins, DeviceKeys.privateKey(), EnvelopeCrypto.publicKeyFromBase64(backendKey))
            sent.save(env, "SEALED")
            sendPacket(device, Wire.toJson(env).toByteArray())
            sent.save(env, "TRANSFERRED")
            runOnUiThread { showInbox() }
            "Request for ₹${amountField.text} handed to $to.\nNOT PAID YET: it is pending until $to submits it online."
        }
    }

    // shortcut: manual forwarding to one paired phone at a time; automatic gossip needs BLE/Nearby Connections with strangers.
    private fun forwardCarried() {
        if (!hasBluetoothPermission()) return
        val device = pairedDevices.getOrNull(deviceSpinner.selectedItemPosition) ?: return log("Pick a paired phone")
        val packets = carried.all().filter { it.status == "CARRYING" }
        if (packets.isEmpty()) return log("Not carrying any packets")
        background {
            val sentCount = packets.count { runCatching { sendPacket(device, Wire.toJson(it.envelope).toByteArray()) }.isSuccess }
            "Forwarded $sentCount of ${packets.size} carried packet(s). Kept copies too: whoever gets online first uploads, duplicates are harmless."
        }
    }

    private fun toggleReceiving() {
        receiver?.let {
            it.stop(); receiver = null; receiveButton.text = "Start receiving"; return log("Stopped receiving")
        }
        if (!hasBluetoothPermission()) return
        val myId = prefs.getString("id", null) ?: return log("Register first")
        val adapter = bluetooth ?: return log("No Bluetooth on this phone")
        receiver = BluetoothReceiver(adapter,
            onPacket = { bytes ->
                val env = Wire.fromJson(String(bytes))
                if (env.receiverId == myId) {
                    if (!inbox.contains(env.transactionId)) inbox.save(env, "RECEIVED")
                    runOnUiThread { log("Received request ${env.transactionId.take(8)} from ${env.senderId} (not paid yet)"); showInbox() }
                } else if (env.senderId != myId) {
                    // Not for us: carry it for the mesh. contains() stops a packet bouncing back and forth.
                    if (!carried.contains(env.transactionId)) carried.save(env, "CARRYING")
                    runOnUiThread { log("Carrying a packet for ${env.receiverId} (can't read it)"); showInbox() }
                }
            },
            onError = { e -> runOnUiThread { log("Receive failed: ${e.message}") } },
        ).also {
            try {
                it.start()
            } catch (e: IOException) {
                receiver = null
                return log("Could not start: ${e.message}")
            }
        }
        receiveButton.text = "Stop receiving"
        log("Waiting for a paired phone to send…")
    }

    /** Submits every packet in [store] still in [pendingStatus] and records the backend's final answer. */
    private fun sync(store: PacketStore, pendingStatus: String) {
        val url = prefs.getString("url", null) ?: return log("Log in first")
        val token = prefs.getString("token", null) ?: return log("Log in first")
        background {
            val client = BackendClient(url, token)
            val lines = store.all().filter { it.status == pendingStatus }.map { stored ->
                val id = stored.envelope.transactionId.take(8)
                try {
                    // A relay gets 202 with no status: it delivered, but isn't told the outcome.
                    val status = client.submit(Wire.toJson(stored.envelope)).optString("status", "DELIVERED")
                    store.save(stored.envelope, status)
                    "$id: $status"
                } catch (e: BackendClient.HttpError) {
                    // 401 is our login, not the packet: keep it and retry after logging in again.
                    if (e.code in 400..499 && e.code != 401) store.save(stored.envelope, "REJECTED").let { "$id: REJECTED (${e.message})" }
                    else "$id: will retry (${e.message})"
                } catch (e: IOException) {
                    "$id: will retry (${e.message})" // offline or lost response; resubmitting is safe
                }
            }
            runOnUiThread { showInbox() }
            if (lines.isEmpty()) "Nothing to sync" else lines.joinToString("\n")
        }
    }

    private fun showInbox() {
        val received = inbox.all().map { "IN  ${it.envelope.transactionId.take(8)} from ${it.envelope.senderId}: ${it.status}" }
        val sentLines = sent.all().map { "OUT ${it.envelope.transactionId.take(8)} to ${it.envelope.receiverId}: ${it.status}" }
        val carriedLines = carried.all().map { "CARRY ${it.envelope.transactionId.take(8)} for ${it.envelope.receiverId}: ${it.status}" }
        inboxView.text = (received + sentLines + carriedLines).ifEmpty { listOf("No requests yet") }.joinToString("\n")
    }

    private fun refreshDevices() {
        if (!hasBluetoothPermission()) return
        @Suppress("MissingPermission")
        pairedDevices = bluetooth?.bondedDevices?.toList().orEmpty()
        @Suppress("MissingPermission")
        val names = pairedDevices.map { "${it.name ?: "Unknown"} (${it.address})" }
        deviceSpinner.adapter = ArrayAdapter(this, android.R.layout.simple_spinner_dropdown_item, names)
        if (names.isEmpty()) log("No paired phones. Pair in system Bluetooth settings, then refresh.")
    }

    private fun hasBluetoothPermission(): Boolean {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.S) return true
        if (checkSelfPermission(Manifest.permission.BLUETOOTH_CONNECT) == PackageManager.PERMISSION_GRANTED) return true
        requestPermissions(arrayOf(Manifest.permission.BLUETOOTH_CONNECT), 1)
        log("Allow Bluetooth access, then try again")
        return false
    }

    override fun onRequestPermissionsResult(requestCode: Int, permissions: Array<out String>, grantResults: IntArray) {
        if (grantResults.firstOrNull() == PackageManager.PERMISSION_GRANTED) refreshDevices()
    }

    /** Runs [task] off the main thread and logs its result or error. */
    private fun background(task: () -> String) {
        thread {
            val msg = try { task() } catch (e: Exception) { "Failed: ${e.message ?: e.javaClass.simpleName}" }
            runOnUiThread { log(msg) }
        }
    }

    private fun log(msg: String) {
        logView.text = "$msg\n\n${logView.text}"
    }

    private fun LinearLayout.heading(text: String) = addView(TextView(context).apply {
        this.text = text; textSize = 18f; setPadding(0, 32, 0, 8)
    })

    private fun LinearLayout.field(hint: String, value: String) = EditText(context).apply {
        this.hint = hint; setText(value); isSingleLine = true
    }.also { addView(it) }

    private fun LinearLayout.button(text: String, onClick: () -> Unit) = Button(context).apply {
        this.text = text; setOnClickListener(View.OnClickListener { onClick() })
    }.also { addView(it) }
}
