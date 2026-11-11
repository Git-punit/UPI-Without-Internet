package com.upioffline.backend;

import com.upioffline.protocol.Envelope;
import com.upioffline.protocol.EnvelopeCrypto;
import com.upioffline.protocol.InvalidEnvelopeException;
import com.upioffline.protocol.PaymentInstruction;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Service;

import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.PublicKey;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Optional;

@Service
public class TransactionService {

    public record TransactionView(String transactionId, String status, String senderId, String receiverId,
                                  long amountMinor, String currency, String failureReason, Instant submittedAt) {
    }

    /** {@code party}: the caller is the sender or receiver. A relaying stranger must not see the details. */
    public record Submission(boolean created, boolean party, TransactionView transaction) {
    }

    record Device(String username, String publicKey, Instant revokedAt) {
    }

    private static final String VIEW_SQL = """
            SELECT t.transaction_id, t.status, t.sender_id, t.receiver_id, t.amount_minor, t.currency,
                   t.failure_reason, t.submitted_at
            FROM transactions t
            JOIN devices s ON s.device_id = t.sender_id
            JOIN devices r ON r.device_id = t.receiver_id
            """;

    private final JdbcClient jdbc;
    private final Ledger ledger;
    private final KeyPair backendKeys;
    private final Duration maxTtl;

    public TransactionService(JdbcClient jdbc, Ledger ledger, KeyPair backendKeys, @Value("${upi.max-ttl}") Duration maxTtl) {
        this.jdbc = jdbc;
        this.ledger = ledger;
        this.backendKeys = backendKeys;
        this.maxTtl = maxTtl;
    }

    /**
     * Anyone logged in may submit: in mesh mode a stranger's phone (a "bridge") carries the packet to the backend.
     * The packet is signed by the sender and bound to the receiver, so the carrier cannot change it.
     */
    public Submission submit(Envelope envelope, String caller) {
        if (envelope.senderId() == null || envelope.receiverId() == null) throw invalid("missing device ids");
        Device sender = activeDevice(envelope.senderId(), "sender");
        Device receiver = activeDevice(envelope.receiverId(), "receiver");

        PaymentInstruction ins;
        try {
            ins = EnvelopeCrypto.open(envelope, backendKeys.getPrivate(), id -> id.equals(envelope.senderId()) ? key(sender) : null);
        } catch (InvalidEnvelopeException e) {
            if ("bad signature".equals(e.getMessage()))
                throw new ApiException(HttpStatus.UNPROCESSABLE_CONTENT, "INVALID_SIGNATURE", "sender signature does not verify");
            throw invalid(e.getMessage());
        }
        // On verified ids: the envelope's ids are bound to the ciphertext, so open() has confirmed them.
        boolean party = caller.equals(sender.username()) || caller.equals(receiver.username());

        String hash = EnvelopeCrypto.fingerprint(ins);
        // Check for a replay before expiry: a receiver retrying after a lost response must get the real outcome.
        Optional<Submission> replay = existing(ins.transactionId(), hash, party);
        if (replay.isPresent()) return replay.get();

        if (!Instant.now().isBefore(ins.expiresAt()))
            throw new ApiException(HttpStatus.GONE, "TRANSACTION_EXPIRED", "instruction expired before it was submitted");
        if (Duration.between(ins.createdAt(), ins.expiresAt()).compareTo(maxTtl) > 0) throw invalid("validity window too long");
        // Without this, a future createdAt would let a packet stay valid for longer than max-ttl from now.
        if (ins.createdAt().isAfter(Instant.now().plus(Duration.ofMinutes(5)))) throw invalid("created in the future (check phone clock)");
        if (!"INR".equals(ins.currency())) throw invalid("only INR supported");

        try {
            ledger.settle(ins, hash, sender.username(), receiver.username());
        } catch (DuplicateKeyException e) {
            // Lost a race with a concurrent submission of the same id.
            return existing(ins.transactionId(), hash, party).orElseThrow();
        }
        return new Submission(true, party, find(ins.transactionId()).orElseThrow());
    }

    public List<TransactionView> history(String username) {
        return jdbc.sql(VIEW_SQL + " WHERE s.username = ? OR r.username = ? ORDER BY t.submitted_at DESC LIMIT 200")
                .params(username, username).query(TransactionView.class).list();
    }

    /** Empty both when missing and when the caller isn't a party, so ids of other people's payments don't leak. */
    public Optional<TransactionView> findVisible(String transactionId, String username) {
        return jdbc.sql(VIEW_SQL + " WHERE t.transaction_id = ? AND (s.username = ? OR r.username = ?)")
                .params(transactionId, username, username).query(TransactionView.class).optional();
    }

    private Optional<TransactionView> find(String transactionId) {
        return jdbc.sql(VIEW_SQL + " WHERE t.transaction_id = ?").param(transactionId).query(TransactionView.class).optional();
    }

    private Optional<Submission> existing(String transactionId, String hash, boolean party) {
        Optional<String> stored = jdbc.sql("SELECT payload_hash FROM transactions WHERE transaction_id = ?")
                .param(transactionId).query(String.class).optional();
        if (stored.isEmpty()) return Optional.empty();
        if (!stored.get().equals(hash))
            throw new ApiException(HttpStatus.CONFLICT, "DUPLICATE_TRANSACTION", "transaction id already used with different details");
        return Optional.of(new Submission(false, party, find(transactionId).orElseThrow()));
    }

    private Device activeDevice(String deviceId, String role) {
        Device d = jdbc.sql("SELECT username, public_key, revoked_at FROM devices WHERE device_id = ?")
                .param(deviceId).query(Device.class).optional()
                .orElseThrow(() -> new ApiException(HttpStatus.FORBIDDEN, "DEVICE_NOT_AUTHORIZED", "unknown " + role + " device"));
        if (d.revokedAt() != null)
            throw new ApiException(HttpStatus.FORBIDDEN, "DEVICE_REVOKED", role + " device has been revoked");
        return d;
    }

    private static PublicKey key(Device d) {
        try {
            return EnvelopeCrypto.publicKeyFromBase64(d.publicKey());
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("stored key unreadable", e);
        }
    }

    private static ApiException invalid(String message) {
        return new ApiException(HttpStatus.BAD_REQUEST, "INVALID_PACKET", message);
    }
}
