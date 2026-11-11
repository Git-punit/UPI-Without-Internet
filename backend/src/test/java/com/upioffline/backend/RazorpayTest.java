package com.upioffline.backend;

import org.junit.jupiter.api.Test;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.client.RestClient;

import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.*;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;

/** The exact requests sent to Razorpay, and webhook signature checking. */
class RazorpayTest {

    @Test
    void payoutRequestIsUpiWithIdempotencyKeyAndBasicAuth() {
        RestClient.Builder builder = RestClient.builder();
        MockRestServiceServer server = MockRestServiceServer.bindTo(builder).build();
        Razorpay rzp = new Razorpay(builder, "https://api.razorpay.com", "rzp_test_key", "secret", "", "2323230000000000");
        String auth = "Basic " + Base64.getEncoder().encodeToString("rzp_test_key:secret".getBytes());

        server.expect(requestTo("https://api.razorpay.com/v1/payouts")).andExpect(method(HttpMethod.POST))
                .andExpect(header("Authorization", auth))
                .andExpect(header("X-Payout-Idempotency", "w-123"))
                .andExpect(jsonPath("$.mode").value("UPI"))
                .andExpect(jsonPath("$.amount").value(30000))
                .andExpect(jsonPath("$.fund_account.vpa.address").value("me@okbank"))
                .andExpect(jsonPath("$.account_number").value("2323230000000000"))
                .andRespond(withSuccess("{\"id\":\"pout_1\",\"status\":\"processing\"}", MediaType.APPLICATION_JSON));

        assertTrue(rzp.createPayout("w-123", 30000, "me@okbank", "alice").get("status").equals("processing"));
        server.verify();
    }

    @Test
    void paymentLinkRequestCarriesOurReference() {
        RestClient.Builder builder = RestClient.builder();
        MockRestServiceServer server = MockRestServiceServer.bindTo(builder).build();
        Razorpay rzp = new Razorpay(builder, "https://api.razorpay.com", "rzp_test_key", "secret", "", "");
        server.expect(requestTo("https://api.razorpay.com/v1/payment_links")).andExpect(method(HttpMethod.POST))
                .andExpect(jsonPath("$.reference_id").value("t-1")).andExpect(jsonPath("$.currency").value("INR"))
                .andRespond(withSuccess("{\"id\":\"plink_1\",\"short_url\":\"https://rzp.io/i/x\"}", MediaType.APPLICATION_JSON));
        assertTrue(rzp.createPaymentLink("t-1", 50000, "alice").get("short_url").equals("https://rzp.io/i/x"));
        server.verify();
    }

    @Test
    void webhookSignature() {
        // Known-answer: HMAC-SHA256("{\"a\":1}", "whsec") in hex.
        String body = "{\"a\":1}";
        String sig = java.util.HexFormat.of().formatHex(hmac(body, "whsec"));
        assertTrue(Razorpay.signatureValid(body, sig, "whsec"));
        assertFalse(Razorpay.signatureValid(body + " ", sig, "whsec"));
        assertFalse(Razorpay.signatureValid(body, sig, "other-secret"));
        assertFalse(Razorpay.signatureValid(body, null, "whsec"));
    }

    private static byte[] hmac(String body, String secret) {
        try {
            var mac = javax.crypto.Mac.getInstance("HmacSHA256");
            mac.init(new javax.crypto.spec.SecretKeySpec(secret.getBytes(), "HmacSHA256"));
            return mac.doFinal(body.getBytes());
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }
}
