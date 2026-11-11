package com.upioffline.protocol;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Arrays;
import java.util.UUID;
import java.util.regex.Pattern;

/**
 * What the sender authorises: pay {@code amountMinor} (paise for INR) from sender to receiver, valid until
 * {@code expiresAt}. This is what gets signed, so its byte form must be exactly one canonical encoding.
 */
public record PaymentInstruction(int protocolVersion, String transactionId, String senderId, String receiverId,
                                 long amountMinor, String currency, Instant createdAt, Instant expiresAt) {

    public static final int VERSION = 1;
    private static final Pattern ID = Pattern.compile("[A-Za-z0-9._-]{1,64}");
    private static final Pattern CURRENCY = Pattern.compile("[A-Z]{3}");
    private static final String[] KEYS = {"v", "id", "from", "to", "amount", "currency", "created", "expires"};

    public PaymentInstruction {
        if (protocolVersion != VERSION) throw new IllegalArgumentException("unsupported protocol version");
        if (transactionId == null || !UUID.fromString(transactionId).toString().equals(transactionId))
            throw new IllegalArgumentException("transactionId must be a lowercase UUID");
        if (!isValidId(senderId) || !isValidId(receiverId)) throw new IllegalArgumentException("invalid device id");
        if (senderId.equals(receiverId)) throw new IllegalArgumentException("sender and receiver must differ");
        if (amountMinor <= 0) throw new IllegalArgumentException("amount must be positive");
        if (currency == null || !CURRENCY.matcher(currency).matches()) throw new IllegalArgumentException("invalid currency");
        if (createdAt == null || expiresAt == null || !expiresAt.isAfter(createdAt))
            throw new IllegalArgumentException("expiresAt must be after createdAt");
    }

    public static PaymentInstruction create(String senderId, String receiverId, long amountMinor, String currency, Duration ttl) {
        Instant now = Instant.now().truncatedTo(ChronoUnit.SECONDS);
        return new PaymentInstruction(VERSION, UUID.randomUUID().toString(), senderId, receiverId,
                amountMinor, currency, now, now.plus(ttl));
    }

    public static boolean isValidId(String id) {
        return id != null && ID.matcher(id).matches();
    }

    /** One {@code key=value} line per field, fixed order. Fields are validated, so none can contain a newline. */
    public byte[] canonicalBytes() {
        String[] values = values();
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < KEYS.length; i++) sb.append(KEYS[i]).append('=').append(values[i]).append('\n');
        return sb.toString().getBytes(StandardCharsets.UTF_8);
    }

    public static PaymentInstruction fromCanonicalBytes(byte[] bytes) {
        try {
            String[] lines = new String(bytes, StandardCharsets.UTF_8).split("\n", -1);
            if (lines.length != KEYS.length + 1 || !lines[KEYS.length].isEmpty())
                throw new IllegalArgumentException("wrong field count");
            String[] v = new String[KEYS.length];
            for (int i = 0; i < KEYS.length; i++) {
                if (!lines[i].startsWith(KEYS[i] + "=")) throw new IllegalArgumentException("unexpected field " + i);
                v[i] = lines[i].substring(KEYS[i].length() + 1);
            }
            PaymentInstruction p = new PaymentInstruction(Integer.parseInt(v[0]), v[1], v[2], v[3],
                    Long.parseLong(v[4]), v[5], Instant.parse(v[6]), Instant.parse(v[7]));
            // Reject alternative spellings ("+5", "007", odd timestamp formats) so one signature = one byte string.
            if (!Arrays.equals(p.canonicalBytes(), bytes)) throw new IllegalArgumentException("not canonical");
            return p;
        } catch (RuntimeException e) {
            throw new IllegalArgumentException("invalid instruction encoding", e);
        }
    }

    private String[] values() {
        return new String[]{String.valueOf(protocolVersion), transactionId, senderId, receiverId,
                String.valueOf(amountMinor), currency, createdAt.toString(), expiresAt.toString()};
    }
}
