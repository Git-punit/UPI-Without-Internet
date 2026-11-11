package com.upioffline.protocol;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.time.Duration;
import java.util.Base64;
import java.util.function.Function;

import static org.junit.jupiter.api.Assertions.*;

class EnvelopeCryptoTest {

    static KeyPair sender, backend, attacker;

    @BeforeAll
    static void keys() throws Exception {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
        gen.initialize(2048);
        sender = gen.generateKeyPair();
        backend = gen.generateKeyPair();
        attacker = gen.generateKeyPair();
    }

    static final Function<String, PublicKey> KEYS = id -> id.equals("alice") ? sender.getPublic() : null;

    static PaymentInstruction instruction() {
        return PaymentInstruction.create("alice", "bob", 50_00, "INR", Duration.ofHours(1));
    }

    @Test
    void roundTrip() throws Exception {
        PaymentInstruction ins = instruction();
        Envelope env = EnvelopeCrypto.seal(ins, sender.getPrivate(), backend.getPublic());
        assertEquals(ins, EnvelopeCrypto.open(env, backend.getPrivate(), KEYS));
        assertFalse(env.ciphertext().contains("5000"), "amount must not be visible");
    }

    @Test
    void tamperedCiphertextRejected() throws Exception {
        Envelope env = EnvelopeCrypto.seal(instruction(), sender.getPrivate(), backend.getPublic());
        byte[] ct = Base64.getDecoder().decode(env.ciphertext());
        ct[10] ^= 1;
        Envelope bad = new Envelope(env.protocolVersion(), env.transactionId(), env.senderId(), env.receiverId(),
                env.nonce(), env.encryptedKey(), Base64.getEncoder().encodeToString(ct));
        assertThrows(InvalidEnvelopeException.class, () -> EnvelopeCrypto.open(bad, backend.getPrivate(), KEYS));
    }

    @Test
    void changedReceiverInHeaderRejected() throws Exception {
        Envelope env = EnvelopeCrypto.seal(instruction(), sender.getPrivate(), backend.getPublic());
        Envelope bad = new Envelope(env.protocolVersion(), env.transactionId(), env.senderId(), "mallory",
                env.nonce(), env.encryptedKey(), env.ciphertext());
        assertThrows(InvalidEnvelopeException.class, () -> EnvelopeCrypto.open(bad, backend.getPrivate(), KEYS));
    }

    @Test
    void signatureFromWrongKeyRejected() throws Exception {
        Envelope env = EnvelopeCrypto.seal(instruction(), attacker.getPrivate(), backend.getPublic());
        InvalidEnvelopeException e = assertThrows(InvalidEnvelopeException.class,
                () -> EnvelopeCrypto.open(env, backend.getPrivate(), KEYS));
        assertEquals("bad signature", e.getMessage());
    }

    @Test
    void unknownSenderRejected() throws Exception {
        Envelope env = EnvelopeCrypto.seal(instruction(), sender.getPrivate(), backend.getPublic());
        assertThrows(InvalidEnvelopeException.class, () -> EnvelopeCrypto.open(env, backend.getPrivate(), id -> null));
    }

    @Test
    void wrongBackendKeyCannotOpen() throws Exception {
        Envelope env = EnvelopeCrypto.seal(instruction(), sender.getPrivate(), backend.getPublic());
        assertThrows(InvalidEnvelopeException.class, () -> EnvelopeCrypto.open(env, attacker.getPrivate(), KEYS));
    }

    @Test
    void canonicalEncodingRoundTripsAndRejectsVariants() {
        PaymentInstruction ins = instruction();
        assertEquals(ins, PaymentInstruction.fromCanonicalBytes(ins.canonicalBytes()));
        String variant = new String(ins.canonicalBytes(), StandardCharsets.UTF_8).replace("amount=5000", "amount=+5000");
        assertThrows(IllegalArgumentException.class,
                () -> PaymentInstruction.fromCanonicalBytes(variant.getBytes(StandardCharsets.UTF_8)));
    }

    @Test
    void invalidInstructionsRejected() {
        assertThrows(IllegalArgumentException.class, () -> PaymentInstruction.create("alice", "alice", 1, "INR", Duration.ofHours(1)));
        assertThrows(IllegalArgumentException.class, () -> PaymentInstruction.create("alice", "bob", 0, "INR", Duration.ofHours(1)));
        assertThrows(IllegalArgumentException.class, () -> PaymentInstruction.create("al\nice", "bob", 1, "INR", Duration.ofHours(1)));
        assertThrows(IllegalArgumentException.class, () -> PaymentInstruction.create("alice", "bob", 1, "INR", Duration.ZERO));
    }
}
