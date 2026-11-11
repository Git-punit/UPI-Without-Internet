package com.upioffline.backend;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.HexFormat;
import java.util.Map;

/**
 * The real UPI rail, via Razorpay: Payment Links to top up a wallet, RazorpayX Payouts to a UPI ID to withdraw.
 * Keys come from the environment only. Use test-mode keys (rzp_test_...) for this prototype.
 */
@Component
public class Razorpay {

    private final RestClient http;
    private final String keyId;
    private final String webhookSecret;
    private final String payoutAccount;

    @Autowired
    public Razorpay(@Value("${upi.razorpay.base-url}") String baseUrl,
                    @Value("${upi.razorpay.key-id}") String keyId,
                    @Value("${upi.razorpay.key-secret}") String keySecret,
                    @Value("${upi.razorpay.webhook-secret}") String webhookSecret,
                    @Value("${upi.razorpay.payout-account}") String payoutAccount) {
        this(RestClient.builder(), baseUrl, keyId, keySecret, webhookSecret, payoutAccount);
    }

    /** Tests pass a builder bound to a mock server. */
    Razorpay(RestClient.Builder builder, String baseUrl, String keyId, String keySecret, String webhookSecret, String payoutAccount) {
        this.keyId = keyId;
        this.webhookSecret = webhookSecret;
        this.payoutAccount = payoutAccount;
        this.http = builder.baseUrl(baseUrl).defaultHeaders(h -> h.setBasicAuth(keyId, keySecret)).build();
    }

    void requireConfigured(boolean payouts) {
        if (keyId.isBlank() || (payouts && payoutAccount.isBlank()))
            throw new ApiException(HttpStatus.SERVICE_UNAVAILABLE, "PAYMENT_SERVICE_UNAVAILABLE",
                    "UPI gateway not configured: set RAZORPAY_KEY_ID and RAZORPAY_KEY_SECRET"
                            + (payouts ? " and RAZORPAYX_ACCOUNT_NUMBER" : ""));
    }

    /** A hosted page where the user pays with any UPI app. {@code referenceId} is our top-up id. */
    @SuppressWarnings("unchecked")
    Map<String, Object> createPaymentLink(String referenceId, long amountMinor, String username) {
        return http.post().uri("/v1/payment_links").body(Map.of(
                "amount", amountMinor, "currency", "INR", "reference_id", referenceId,
                "description", "UPI Offline wallet top-up", "notes", Map.of("username", username)
        )).retrieve().body(Map.class);
    }

    @SuppressWarnings("unchecked")
    Map<String, Object> getPaymentLink(String linkId) {
        return http.get().uri("/v1/payment_links/{id}", linkId).retrieve().body(Map.class);
    }

    /**
     * Pays {@code amountMinor} to a UPI ID. {@code referenceId} is also the idempotency key, so retrying after a
     * timeout cannot pay twice.
     */
    @SuppressWarnings("unchecked")
    Map<String, Object> createPayout(String referenceId, long amountMinor, String vpa, String username) {
        return http.post().uri("/v1/payouts").header("X-Payout-Idempotency", referenceId).body(Map.of(
                "account_number", payoutAccount, "amount", amountMinor, "currency", "INR",
                "mode", "UPI", "purpose", "payout", "queue_if_low_balance", true, "reference_id", referenceId,
                "fund_account", Map.of("account_type", "vpa", "vpa", Map.of("address", vpa),
                        "contact", Map.of("name", username, "type", "customer", "reference_id", username))
        )).retrieve().body(Map.class);
    }

    @SuppressWarnings("unchecked")
    Map<String, Object> getPayout(String payoutId) {
        return http.get().uri("/v1/payouts/{id}", payoutId).retrieve().body(Map.class);
    }

    boolean webhookValid(String body, String signature) {
        return !webhookSecret.isBlank() && signatureValid(body, signature, webhookSecret);
    }

    /** Razorpay signs webhooks with hex HMAC-SHA256 of the raw body. Constant-time compare. */
    static boolean signatureValid(String body, String signature, String secret) {
        if (body == null || signature == null) return false;
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
            byte[] expected = HexFormat.of().formatHex(mac.doFinal(body.getBytes(StandardCharsets.UTF_8))).getBytes(StandardCharsets.UTF_8);
            return MessageDigest.isEqual(expected, signature.getBytes(StandardCharsets.UTF_8));
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }
}
