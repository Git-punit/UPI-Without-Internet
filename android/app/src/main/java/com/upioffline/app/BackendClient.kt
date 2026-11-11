package com.upioffline.app

import org.json.JSONObject
import java.io.IOException
import java.net.HttpURLConnection
import java.net.URL

/** [token] is the login session; every call except register/login/backendKey needs it. */
class BackendClient(private val baseUrl: String, private val token: String? = null) {

    /** [error] is the backend's code, e.g. TRANSACTION_EXPIRED or DEVICE_REVOKED. */
    class HttpError(val code: Int, val error: String, message: String) : IOException("$error: $message")

    fun registerUser(username: String, password: String) {
        request("POST", "/api/v1/auth/register", JSONObject().put("username", username).put("password", password).toString())
    }

    /** Returns a session token. */
    fun login(username: String, password: String): String =
        JSONObject(request("POST", "/api/v1/auth/login",
            JSONObject().put("username", username).put("password", password).toString())).getString("token")

    fun registerDevice(deviceId: String, publicKeyBase64: String, proofBase64: String) {
        request("POST", "/api/v1/devices/register", JSONObject()
            .put("deviceId", deviceId).put("publicKey", publicKeyBase64).put("proof", proofBase64).toString())
    }

    fun backendKey(): String = JSONObject(request("GET", "/api/v1/keys/backend", null)).getString("publicKey")

    /** Returns the backend's verdict: SUCCESS or FAILED. 4xx means the packet itself was refused. */
    fun submit(envelopeJson: String): JSONObject = JSONObject(request("POST", "/api/v1/transactions", envelopeJson))

    private fun request(method: String, path: String, body: String?): String {
        val conn = URL(baseUrl.trimEnd('/') + path).openConnection() as HttpURLConnection
        try {
            conn.requestMethod = method
            conn.connectTimeout = 10_000
            conn.readTimeout = 10_000
            if (token != null) conn.setRequestProperty("Authorization", "Bearer $token")
            if (body != null) {
                conn.doOutput = true
                conn.setRequestProperty("Content-Type", "application/json")
                conn.outputStream.use { it.write(body.toByteArray()) }
            }
            val code = conn.responseCode
            if (code !in 200..299) {
                val err = runCatching { JSONObject(conn.errorStream.bufferedReader().readText()) }.getOrNull()
                throw HttpError(code, err?.optString("error").orEmpty().ifEmpty { "HTTP_$code" }, err?.optString("message").orEmpty())
            }
            return conn.inputStream.bufferedReader().readText()
        } finally {
            conn.disconnect()
        }
    }
}
