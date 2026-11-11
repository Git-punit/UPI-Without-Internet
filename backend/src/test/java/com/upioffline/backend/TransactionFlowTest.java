package com.upioffline.backend;

import com.upioffline.protocol.Envelope;
import com.upioffline.protocol.EnvelopeCrypto;
import com.upioffline.protocol.PaymentInstruction;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import tools.jackson.databind.json.JsonMapper;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import static org.hamcrest.Matchers.hasSize;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/** Sender seals offline → receiver carries the packet (as JSON) → receiver, logged in, submits it. */
@SpringBootTest(properties = "upi.key-file=target/test-backend-key.der")
@AutoConfigureMockMvc
class TransactionFlowTest {

    @Autowired MockMvc mvc;
    @Autowired JsonMapper json;
    @Autowired JdbcClient jdbc;
    @Autowired TransactionService service;

    static final KeyPair SENDER_KEYS = rsa();
    static final KeyPair RECEIVER_KEYS = rsa();
    String alice, bob;             // usernames
    String aliceToken, bobToken;
    String sender, receiver;       // device ids
    PublicKey backendKey;

    @BeforeEach
    void setUp() throws Exception {
        alice = "alice-" + shortId();
        bob = "bob-" + shortId();
        aliceToken = signUp(alice);
        bobToken = signUp(bob);
        sender = "phone-" + shortId();
        receiver = "phone-" + shortId();
        registerDevice(aliceToken, alice, sender, SENDER_KEYS).andExpect(status().isCreated());
        registerDevice(bobToken, bob, receiver, RECEIVER_KEYS).andExpect(status().isCreated());
        String body = mvc.perform(get("/api/v1/keys/backend")).andReturn().getResponse().getContentAsString();
        backendKey = EnvelopeCrypto.publicKeyFromBase64(json.readValue(body, Map.class).get("publicKey").toString());
    }

    @Test
    void validPacketSettlesBetweenUsers() throws Exception {
        Envelope env = seal(250_00);
        submit(bobToken, env).andExpect(status().isCreated()).andExpect(jsonPath("$.status").value("SUCCESS"));
        assertEquals(100000 - 25000, balance(alice));
        assertEquals(100000 + 25000, balance(bob));
        mvc.perform(auth(get("/api/v1/me"), aliceToken)).andExpect(jsonPath("$.balanceMinor").value(75000));
    }

    @Test
    void senderCanSubmitOwnCopyAndBothSeeIt() throws Exception {
        Envelope env = seal(100_00);
        submit(aliceToken, env).andExpect(status().isCreated());
        submit(bobToken, env).andExpect(status().isOk()).andExpect(jsonPath("$.status").value("SUCCESS"));
        assertEquals(90000, balance(alice));
        mvc.perform(auth(get("/api/v1/transactions"), aliceToken)).andExpect(jsonPath("$", hasSize(1)));
        mvc.perform(auth(get("/api/v1/transactions/" + env.transactionId()), bobToken)).andExpect(status().isOk());
    }

    @Test
    void strangerRelaySettlesButLearnsNothing() throws Exception {
        // Mesh mode: Carol's phone carried the packet and is the first to get online.
        String carol = "carol-" + shortId();
        String carolToken = signUp(carol);
        Envelope env = seal(100_00);
        submit(carolToken, env).andExpect(status().isAccepted())
                .andExpect(jsonPath("$.delivered").value(true))
                .andExpect(jsonPath("$.amountMinor").doesNotExist())
                .andExpect(jsonPath("$.status").doesNotExist());
        assertEquals(90000, balance(alice));
        // A second bridge delivering the same packet changes nothing; the receiver then sees the real outcome.
        submit(carolToken, env).andExpect(status().isAccepted());
        submit(bobToken, env).andExpect(status().isOk()).andExpect(jsonPath("$.status").value("SUCCESS"));
        assertEquals(90000, balance(alice));
        mvc.perform(auth(get("/api/v1/transactions/" + env.transactionId()), carolToken))
                .andExpect(status().isNotFound()).andExpect(jsonPath("$.error").value("TRANSACTION_NOT_FOUND"));
        mvc.perform(auth(get("/api/v1/transactions"), carolToken)).andExpect(jsonPath("$", hasSize(0)));
    }

    @Test
    void requestsWithoutLoginRejected() throws Exception {
        mvc.perform(post("/api/v1/transactions").contentType(MediaType.APPLICATION_JSON).content(json.writeValueAsString(seal(100))))
                .andExpect(status().isUnauthorized()).andExpect(jsonPath("$.error").value("UNAUTHORIZED"));
        mvc.perform(auth(get("/api/v1/me"), "made-up-token")).andExpect(status().isUnauthorized());
    }

    @Test
    void logoutEndsSession() throws Exception {
        mvc.perform(auth(post("/api/v1/auth/logout"), aliceToken)).andExpect(status().isNoContent());
        mvc.perform(auth(get("/api/v1/me"), aliceToken)).andExpect(status().isUnauthorized());
    }

    @Test
    void wrongPasswordAndDuplicateUsernameRejected() throws Exception {
        mvc.perform(json(post("/api/v1/auth/login"), Map.of("username", alice, "password", "wrong-password")))
                .andExpect(status().isUnauthorized()).andExpect(jsonPath("$.error").value("INVALID_CREDENTIALS"));
        mvc.perform(json(post("/api/v1/auth/register"), Map.of("username", alice, "password", "another-password")))
                .andExpect(status().isConflict()).andExpect(jsonPath("$.error").value("USERNAME_TAKEN"));
    }

    @Test
    void deviceRegistrationNeedsProofOfKey() throws Exception {
        // Bob tries to register Alice's public key without her private key.
        String body = json.writeValueAsString(Map.of("deviceId", "stolen-" + shortId(),
                "publicKey", EnvelopeCrypto.publicKeyToBase64(SENDER_KEYS.getPublic()),
                "proof", Base64.getEncoder().encodeToString(new byte[256])));
        mvc.perform(auth(post("/api/v1/devices/register"), bobToken).contentType(MediaType.APPLICATION_JSON).content(body))
                .andExpect(status().isUnprocessableContent()).andExpect(jsonPath("$.error").value("INVALID_SIGNATURE"));
        registerDevice(bobToken, bob, sender, RECEIVER_KEYS).andExpect(status().isConflict());
    }

    @Test
    void revokedDevicePacketsRefused() throws Exception {
        Envelope env = seal(100_00); // sealed before the phone was lost
        mvc.perform(auth(delete("/api/v1/devices/" + sender), aliceToken)).andExpect(status().isNoContent());
        submit(bobToken, env).andExpect(status().isForbidden()).andExpect(jsonPath("$.error").value("DEVICE_REVOKED"));
        assertEquals(100000, balance(alice));
        mvc.perform(auth(get("/api/v1/devices/me"), aliceToken)).andExpect(jsonPath("$[0].revokedAt").isNotEmpty());
        // Only the owner can revoke.
        mvc.perform(auth(delete("/api/v1/devices/" + receiver), aliceToken)).andExpect(status().isNotFound());
    }

    @Test
    void concurrentDuplicatesChargeOnce() throws Exception {
        Envelope env = seal(100_00);
        Callable<Boolean> task = () -> service.submit(env, bob).created();
        try (ExecutorService pool = Executors.newFixedThreadPool(2)) {
            List<Boolean> created = pool.invokeAll(List.of(task, task)).stream().map(f -> {
                try { return f.get(); } catch (Exception e) { throw new RuntimeException(e); }
            }).toList();
            assertEquals(1, created.stream().filter(c -> c).count());
        }
        assertEquals(90000, balance(alice));
    }

    @Test
    void sameIdWithDifferentAmountIsConflict() throws Exception {
        PaymentInstruction first = PaymentInstruction.create(sender, receiver, 100_00, "INR", Duration.ofHours(1));
        submit(bobToken, seal(first)).andExpect(status().isCreated());
        PaymentInstruction changed = new PaymentInstruction(1, first.transactionId(), sender, receiver,
                999_00, "INR", first.createdAt(), first.expiresAt());
        submit(bobToken, seal(changed)).andExpect(status().isConflict()).andExpect(jsonPath("$.error").value("DUPLICATE_TRANSACTION"));
        assertEquals(90000, balance(alice));
    }

    @Test
    void expiredPacketRejected() throws Exception {
        Instant now = Instant.now().truncatedTo(ChronoUnit.SECONDS);
        PaymentInstruction old = new PaymentInstruction(1, UUID.randomUUID().toString(), sender, receiver,
                100, "INR", now.minus(Duration.ofHours(2)), now.minus(Duration.ofHours(1)));
        submit(bobToken, seal(old)).andExpect(status().isGone()).andExpect(jsonPath("$.error").value("TRANSACTION_EXPIRED"));
        assertEquals(100000, balance(alice));
    }

    @Test
    void futureDatedPacketRejected() throws Exception {
        Instant future = Instant.now().truncatedTo(ChronoUnit.SECONDS).plus(Duration.ofDays(3));
        PaymentInstruction ins = new PaymentInstruction(1, UUID.randomUUID().toString(), sender, receiver,
                100, "INR", future, future.plus(Duration.ofHours(1)));
        submit(bobToken, seal(ins)).andExpect(status().isBadRequest()).andExpect(jsonPath("$.error").value("INVALID_PACKET"));
        assertEquals(100000, balance(alice));
    }

    @Test
    void tooLongValidityRejected() throws Exception {
        submit(bobToken, seal(PaymentInstruction.create(sender, receiver, 100, "INR", Duration.ofDays(30))))
                .andExpect(status().isBadRequest()).andExpect(jsonPath("$.error").value("INVALID_PACKET"));
    }

    @Test
    void twoOfflinePacketsExceedingBalance_secondFails() throws Exception {
        // Both are validly signed while offline; the backend only lets the funds be spent once.
        submit(bobToken, seal(800_00)).andExpect(jsonPath("$.status").value("SUCCESS"));
        submit(bobToken, seal(800_00))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.status").value("FAILED"))
                .andExpect(jsonPath("$.failureReason").value("INSUFFICIENT_FUNDS"));
        assertEquals(20000, balance(alice));
    }

    @Test
    void receiverCannotRedirectPayment() throws Exception {
        Envelope env = seal(100);
        String other = "phone-" + shortId();
        registerDevice(bobToken, bob, other, RECEIVER_KEYS).andExpect(status().isCreated());
        Envelope redirected = new Envelope(1, env.transactionId(), sender, other, env.nonce(), env.encryptedKey(), env.ciphertext());
        submit(bobToken, redirected).andExpect(status().isBadRequest()).andExpect(jsonPath("$.error").value("INVALID_PACKET"));
    }

    @Test
    void forgedSenderSignatureRejected() throws Exception {
        PaymentInstruction ins = PaymentInstruction.create(sender, receiver, 100, "INR", Duration.ofHours(1));
        submit(bobToken, EnvelopeCrypto.seal(ins, RECEIVER_KEYS.getPrivate(), backendKey))
                .andExpect(status().isUnprocessableContent()).andExpect(jsonPath("$.error").value("INVALID_SIGNATURE"));
    }

    // --- helpers ---

    private Envelope seal(long amountMinor) throws Exception {
        return seal(PaymentInstruction.create(sender, receiver, amountMinor, "INR", Duration.ofHours(1)));
    }

    private Envelope seal(PaymentInstruction ins) throws Exception {
        return EnvelopeCrypto.seal(ins, SENDER_KEYS.getPrivate(), backendKey);
    }

    private ResultActions submit(String token, Envelope env) throws Exception {
        return mvc.perform(auth(post("/api/v1/transactions"), token).contentType(MediaType.APPLICATION_JSON).content(json.writeValueAsString(env)));
    }

    private String signUp(String username) throws Exception {
        Map<String, String> creds = Map.of("username", username, "password", "correct-horse-battery");
        mvc.perform(json(post("/api/v1/auth/register"), creds)).andExpect(status().isCreated());
        String body = mvc.perform(json(post("/api/v1/auth/login"), creds)).andExpect(status().isOk()).andReturn().getResponse().getContentAsString();
        return json.readValue(body, Map.class).get("token").toString();
    }

    private ResultActions registerDevice(String token, String username, String deviceId, KeyPair keys) throws Exception {
        String proof = Base64.getEncoder().encodeToString(
                EnvelopeCrypto.sign(EnvelopeCrypto.registrationMessage(deviceId, username), keys.getPrivate()));
        String body = json.writeValueAsString(Map.of("deviceId", deviceId,
                "publicKey", EnvelopeCrypto.publicKeyToBase64(keys.getPublic()), "proof", proof));
        return mvc.perform(auth(post("/api/v1/devices/register"), token).contentType(MediaType.APPLICATION_JSON).content(body));
    }

    private MockHttpServletRequestBuilder auth(MockHttpServletRequestBuilder req, String token) {
        return req.header("Authorization", "Bearer " + token);
    }

    private MockHttpServletRequestBuilder json(MockHttpServletRequestBuilder req, Object body) {
        return req.contentType(MediaType.APPLICATION_JSON).content(json.writeValueAsString(body));
    }

    private long balance(String username) {
        return jdbc.sql("SELECT balance_minor FROM accounts WHERE username = ?").param(username).query(Long.class).single();
    }

    private static String shortId() {
        return UUID.randomUUID().toString().substring(0, 8);
    }

    private static KeyPair rsa() {
        try {
            KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
            gen.initialize(2048);
            return gen.generateKeyPair();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }
}
