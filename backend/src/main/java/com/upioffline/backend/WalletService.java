package com.upioffline.backend;

import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Service;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestClientException;
import tools.jackson.databind.json.JsonMapper;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.regex.Pattern;

/**
 * Money in and out of the wallet over real UPI (Razorpay). Offline payments then move wallet balance, exactly like
 * NPCI's UPI Lite: you can only spend offline what was loaded while online.
 */
@Service
public class WalletService {

    public record Topup(String topupId, long amountMinor, String paymentUrl, String status, Instant createdAt) {
    }

    public record Withdrawal(String withdrawalId, long amountMinor, String vpa, String status, String failureReason, Instant createdAt) {
    }

    record WithdrawalRow(String username, long amountMinor, String vpa, String payoutId, String status) {
    }

    private static final Pattern VPA = Pattern.compile("[A-Za-z0-9._-]{2,256}@[A-Za-z0-9]{2,64}");
    static final long MIN_MINOR = 100;              // ₹1
    static final long MAX_MINOR = 1_00_000_00;      // ₹1,00,000, the usual UPI per-transaction limit

    private final JdbcClient jdbc;
    private final Ledger ledger;
    private final Razorpay gateway;
    private final JsonMapper json;

    public WalletService(JdbcClient jdbc, Ledger ledger, Razorpay gateway, JsonMapper json) {
        this.jdbc = jdbc;
        this.ledger = ledger;
        this.gateway = gateway;
        this.json = json;
    }

    public Topup createTopup(String username, long amountMinor) {
        checkAmount(amountMinor);
        gateway.requireConfigured(false);
        String id = UUID.randomUUID().toString();
        jdbc.sql("INSERT INTO topups (topup_id, username, amount_minor, status) VALUES (?, ?, ?, 'PENDING')")
                .params(id, username, amountMinor).update();
        Map<String, Object> link;
        try {
            link = gateway.createPaymentLink(id, amountMinor, username);
        } catch (RestClientException e) {
            jdbc.sql("UPDATE topups SET status = 'EXPIRED' WHERE topup_id = ?").param(id).update();
            throw new ApiException(HttpStatus.BAD_GATEWAY, "PAYMENT_SERVICE_ERROR", "could not create UPI payment link: " + brief(e));
        }
        jdbc.sql("UPDATE topups SET link_id = ?, payment_url = ? WHERE topup_id = ?")
                .params(link.get("id"), link.get("short_url"), id).update();
        return topup(username, id);
    }

    /** Asks Razorpay whether the user has paid. Needed locally, where Razorpay's webhook can't reach localhost. */
    public Topup refreshTopup(String username, String topupId) {
        Topup t = topup(username, topupId);
        String linkId = jdbc.sql("SELECT link_id FROM topups WHERE topup_id = ?").param(topupId).query(String.class).single();
        if ("PENDING".equals(t.status()) && linkId != null) {
            try {
                applyLink(topupId, gateway.getPaymentLink(linkId));
            } catch (RestClientException e) {
                throw new ApiException(HttpStatus.BAD_GATEWAY, "PAYMENT_SERVICE_ERROR", "could not reach UPI gateway: " + brief(e));
            }
        }
        return topup(username, topupId);
    }

    public Withdrawal withdraw(String username, long amountMinor, String vpa) {
        checkAmount(amountMinor);
        if (vpa == null || !VPA.matcher(vpa).matches()) throw ApiException.badRequest("UPI ID must look like name@bank");
        gateway.requireConfigured(true);
        String id = UUID.randomUUID().toString();
        ledger.startWithdrawal(id, username, amountMinor, vpa);
        submitPayout(id);
        return withdrawal(username, id);
    }

    /** Reconciles a withdrawal whose outcome is unknown. Never pays twice: the payout id is the idempotency key. */
    public Withdrawal refreshWithdrawal(String username, String withdrawalId) {
        withdrawal(username, withdrawalId); // ownership check
        WithdrawalRow row = row(withdrawalId);
        if ("PENDING".equals(row.status())) {
            if (row.payoutId() == null) submitPayout(withdrawalId);
            else {
                try {
                    applyPayout(withdrawalId, gateway.getPayout(row.payoutId()));
                } catch (RestClientException e) {
                    // still unknown; stays PENDING
                }
            }
        }
        return withdrawal(username, withdrawalId);
    }

    public Map<String, Object> wallet(String username) {
        long balance = jdbc.sql("SELECT balance_minor FROM accounts WHERE username = ?").param(username).query(Long.class).single();
        List<Topup> topups = jdbc.sql("SELECT topup_id, amount_minor, payment_url, status, created_at FROM topups WHERE username = ? ORDER BY created_at DESC LIMIT 50")
                .param(username).query(Topup.class).list();
        List<Withdrawal> withdrawals = jdbc.sql("SELECT withdrawal_id, amount_minor, vpa, status, failure_reason, created_at FROM withdrawals WHERE username = ? ORDER BY created_at DESC LIMIT 50")
                .param(username).query(Withdrawal.class).list();
        return Map.of("balanceMinor", balance, "topups", topups, "withdrawals", withdrawals);
    }

    /** Razorpay's push notification. Only trusted when its HMAC signature matches our webhook secret. */
    @SuppressWarnings("unchecked")
    public void webhook(String body, String signature) {
        if (!gateway.webhookValid(body, signature))
            throw new ApiException(HttpStatus.BAD_REQUEST, "INVALID_SIGNATURE", "webhook signature does not verify");
        Map<String, Object> event = json.readValue(body, Map.class);
        Map<String, Object> payload = (Map<String, Object>) event.getOrDefault("payload", Map.of());
        Map<String, Object> link = entity(payload, "payment_link");
        if (link != null) jdbc.sql("SELECT topup_id FROM topups WHERE link_id = ?").param(link.get("id"))
                .query(String.class).optional().ifPresent(id -> applyLink(id, link));
        Map<String, Object> payout = entity(payload, "payout");
        if (payout != null) jdbc.sql("SELECT withdrawal_id FROM withdrawals WHERE withdrawal_id = ? OR payout_id = ?")
                .params(payout.get("reference_id"), payout.get("id")).query(String.class).optional().ifPresent(id -> applyPayout(id, payout));
    }

    private void submitPayout(String withdrawalId) {
        WithdrawalRow row = row(withdrawalId);
        try {
            applyPayout(withdrawalId, gateway.createPayout(withdrawalId, row.amountMinor(), row.vpa(), row.username()));
        } catch (HttpClientErrorException e) {
            ledger.failWithdrawal(withdrawalId, "rejected by gateway: " + brief(e)); // 4xx: definitely not paid
        } catch (RestClientException e) {
            // Timeout or 5xx: the payout may or may not exist. Keep it PENDING and reconcile; never refund blindly.
            jdbc.sql("UPDATE withdrawals SET failure_reason = 'awaiting gateway confirmation' WHERE withdrawal_id = ? AND status = 'PENDING'")
                    .param(withdrawalId).update();
        }
    }

    private void applyLink(String topupId, Map<String, Object> link) {
        String status = String.valueOf(link.get("status"));
        if ("paid".equals(status)) ledger.creditTopup(topupId);
        else if ("expired".equals(status) || "cancelled".equals(status))
            jdbc.sql("UPDATE topups SET status = 'EXPIRED' WHERE topup_id = ? AND status = 'PENDING'").param(topupId).update();
    }

    @SuppressWarnings("unchecked")
    private void applyPayout(String withdrawalId, Map<String, Object> payout) {
        if (payout.get("id") != null)
            jdbc.sql("UPDATE withdrawals SET payout_id = ? WHERE withdrawal_id = ? AND payout_id IS NULL").params(payout.get("id"), withdrawalId).update();
        String status = String.valueOf(payout.get("status"));
        switch (status) {
            case "processed" -> jdbc.sql("UPDATE withdrawals SET status = 'PAID', failure_reason = NULL WHERE withdrawal_id = ? AND status = 'PENDING'")
                    .param(withdrawalId).update();
            case "failed", "rejected", "reversed", "cancelled" -> {
                Object details = payout.get("status_details") instanceof Map<?, ?> m ? ((Map<String, Object>) m).get("description") : null;
                ledger.failWithdrawal(withdrawalId, "payout " + status + (details != null ? ": " + details : ""));
            }
            default -> { } // queued, pending, processing: not final yet
        }
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> entity(Map<String, Object> payload, String key) {
        return payload.get(key) instanceof Map<?, ?> m && m.get("entity") instanceof Map<?, ?> e ? (Map<String, Object>) e : null;
    }

    private Topup topup(String username, String topupId) {
        return jdbc.sql("SELECT topup_id, amount_minor, payment_url, status, created_at FROM topups WHERE topup_id = ? AND username = ?")
                .params(topupId, username).query(Topup.class).optional()
                .orElseThrow(() -> new ApiException(HttpStatus.NOT_FOUND, "NOT_FOUND", "no such top-up"));
    }

    private Withdrawal withdrawal(String username, String withdrawalId) {
        return jdbc.sql("SELECT withdrawal_id, amount_minor, vpa, status, failure_reason, created_at FROM withdrawals WHERE withdrawal_id = ? AND username = ?")
                .params(withdrawalId, username).query(Withdrawal.class).optional()
                .orElseThrow(() -> new ApiException(HttpStatus.NOT_FOUND, "NOT_FOUND", "no such withdrawal"));
    }

    private WithdrawalRow row(String withdrawalId) {
        return jdbc.sql("SELECT username, amount_minor, vpa, payout_id, status FROM withdrawals WHERE withdrawal_id = ?")
                .param(withdrawalId).query(WithdrawalRow.class).single();
    }

    private static void checkAmount(long amountMinor) {
        if (amountMinor < MIN_MINOR || amountMinor > MAX_MINOR) throw ApiException.badRequest("amount must be ₹1 to ₹1,00,000");
    }

    private static String brief(RestClientException e) {
        String msg = e instanceof HttpClientErrorException h ? h.getStatusCode() + " " + h.getResponseBodyAsString() : e.getMessage();
        return msg == null ? e.getClass().getSimpleName() : msg.length() > 200 ? msg.substring(0, 200) : msg;
    }
}
