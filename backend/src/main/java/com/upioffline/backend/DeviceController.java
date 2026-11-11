package com.upioffline.backend;

import com.upioffline.protocol.EnvelopeCrypto;
import com.upioffline.protocol.PaymentInstruction;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.web.bind.annotation.*;

import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.Map;

import static com.upioffline.backend.AuthController.USER_ATTR;

@RestController
@RequestMapping("/api/v1")
public class DeviceController {

    /** {@code proof}: the device's RSA-PSS signature over {@link EnvelopeCrypto#registrationMessage}. */
    public record RegisterDeviceRequest(String deviceId, String publicKey, String proof) {
    }

    public record DeviceView(String deviceId, Instant createdAt, Instant revokedAt) {
    }

    private final JdbcClient jdbc;
    private final KeyPair backendKeys;

    public DeviceController(JdbcClient jdbc, KeyPair backendKeys) {
        this.jdbc = jdbc;
        this.backendKeys = backendKeys;
    }

    /** Public. Senders download this while online and keep it, so they can seal packets later offline. */
    @GetMapping("/keys/backend")
    public Map<String, String> backendKey() {
        return Map.of("publicKey", EnvelopeCrypto.publicKeyToBase64(backendKeys.getPublic()));
    }

    @PostMapping("/devices/register")
    @ResponseStatus(HttpStatus.CREATED)
    public Map<String, String> register(@RequestAttribute(USER_ATTR) String username, @RequestBody RegisterDeviceRequest req) {
        if (!PaymentInstruction.isValidId(req.deviceId())) throw ApiException.badRequest("invalid deviceId");
        PublicKey key;
        try {
            key = EnvelopeCrypto.publicKeyFromBase64(req.publicKey());
        } catch (GeneralSecurityException e) {
            throw ApiException.badRequest("invalid publicKey");
        }
        if (((RSAPublicKey) key).getModulus().bitLength() < 2048)
            throw ApiException.badRequest("RSA key must be at least 2048 bits");
        // Proof of possession: stops anyone registering a key they don't hold, or someone else's key under their account.
        boolean proven;
        try {
            proven = req.proof() != null && EnvelopeCrypto.verify(
                    EnvelopeCrypto.registrationMessage(req.deviceId(), username), Base64.getDecoder().decode(req.proof()), key);
        } catch (GeneralSecurityException | IllegalArgumentException e) {
            proven = false;
        }
        if (!proven) throw new ApiException(HttpStatus.UNPROCESSABLE_CONTENT, "INVALID_SIGNATURE", "device key proof does not verify");
        try {
            jdbc.sql("INSERT INTO devices (device_id, username, public_key) VALUES (?, ?, ?)")
                    .params(req.deviceId(), username, EnvelopeCrypto.publicKeyToBase64(key)).update();
        } catch (DuplicateKeyException e) {
            throw new ApiException(HttpStatus.CONFLICT, "DEVICE_ID_TAKEN", "device id already registered");
        }
        return Map.of("deviceId", req.deviceId(), "status", "REGISTERED");
    }

    @GetMapping("/devices/me")
    public List<DeviceView> myDevices(@RequestAttribute(USER_ATTR) String username) {
        return jdbc.sql("SELECT device_id, created_at, revoked_at FROM devices WHERE username = ? ORDER BY created_at")
                .param(username).query(DeviceView.class).list();
    }

    /** For a lost or compromised phone. Packets it signed are refused from now on, even ones already sent. */
    @DeleteMapping("/devices/{deviceId}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void revoke(@RequestAttribute(USER_ATTR) String username, @PathVariable String deviceId) {
        int found = jdbc.sql("UPDATE devices SET revoked_at = COALESCE(revoked_at, ?) WHERE device_id = ? AND username = ?")
                .params(Timestamp.from(Instant.now()), deviceId, username).update();
        if (found == 0) throw new ApiException(HttpStatus.NOT_FOUND, "DEVICE_NOT_FOUND", "no such device on your account");
    }
}
