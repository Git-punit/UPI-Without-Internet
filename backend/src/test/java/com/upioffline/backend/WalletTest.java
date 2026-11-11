package com.upioffline.backend;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.ResourceAccessException;
import tools.jackson.databind.json.JsonMapper;

import java.util.Map;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/** Wallet logic against faked Razorpay answers: credit once, refund only on definite failure, never pay twice. */
@SpringBootTest(properties = "upi.key-file=target/test-backend-key.der")
@AutoConfigureMockMvc
class WalletTest {

    @Autowired MockMvc mvc;
    @Autowired JsonMapper json;
    @Autowired JdbcClient jdbc;
    @MockitoBean Razorpay gateway;

    String user, token;

    @BeforeEach
    void setUp() throws Exception {
        user = "w-" + UUID.randomUUID().toString().substring(0, 8);
        Map<String, String> creds = Map.of("username", user, "password", "correct-horse-battery");
        mvc.perform(post("/api/v1/auth/register").contentType(MediaType.APPLICATION_JSON).content(json.writeValueAsString(creds)));
        String body = mvc.perform(post("/api/v1/auth/login").contentType(MediaType.APPLICATION_JSON).content(json.writeValueAsString(creds)))
                .andReturn().getResponse().getContentAsString();
        token = json.readValue(body, Map.class).get("token").toString();
    }

    @Test
    void topupCreditsOnlyOnceGatewayConfirms() throws Exception {
        when(gateway.createPaymentLink(anyString(), eq(500_00L), eq(user)))
                .thenReturn(Map.of("id", "plink_1" + user, "short_url", "https://rzp.io/test", "status", "created"));
        String topupId = id(call("/wallet/topups", Map.of("amountMinor", 500_00)).andExpect(status().isCreated())
                .andExpect(jsonPath("$.paymentUrl").value("https://rzp.io/test")).andExpect(jsonPath("$.status").value("PENDING")), "topupId");
        assertEquals(100000, balance());

        when(gateway.getPaymentLink("plink_1" + user)).thenReturn(Map.of("id", "plink_1" + user, "status", "created"));
        call("/wallet/topups/" + topupId + "/refresh", null).andExpect(jsonPath("$.status").value("PENDING"));
        assertEquals(100000, balance());

        when(gateway.getPaymentLink("plink_1" + user)).thenReturn(Map.of("id", "plink_1" + user, "status", "paid"));
        call("/wallet/topups/" + topupId + "/refresh", null).andExpect(jsonPath("$.status").value("PAID"));
        call("/wallet/topups/" + topupId + "/refresh", null).andExpect(jsonPath("$.status").value("PAID"));
        assertEquals(150000, balance());
    }

    @Test
    void signedWebhookCreditsOnceAndForgedOneIsIgnored() throws Exception {
        when(gateway.createPaymentLink(anyString(), anyLong(), anyString()))
                .thenReturn(Map.of("id", "plink_2" + user, "short_url", "https://rzp.io/x", "status", "created"));
        call("/wallet/topups", Map.of("amountMinor", 200_00)).andExpect(status().isCreated());
        String event = json.writeValueAsString(Map.of("event", "payment_link.paid",
                "payload", Map.of("payment_link", Map.of("entity", Map.of("id", "plink_2" + user, "status", "paid")))));

        when(gateway.webhookValid(event, "forged")).thenReturn(false);
        webhook(event, "forged").andExpect(status().isBadRequest()).andExpect(jsonPath("$.error").value("INVALID_SIGNATURE"));
        assertEquals(100000, balance());

        when(gateway.webhookValid(event, "good")).thenReturn(true);
        webhook(event, "good").andExpect(status().isOk());
        webhook(event, "good").andExpect(status().isOk()); // Razorpay retries webhooks
        assertEquals(120000, balance());
    }

    @Test
    void withdrawalPaidDebitsWallet() throws Exception {
        when(gateway.createPayout(anyString(), eq(300_00L), eq("me@okbank"), eq(user)))
                .thenReturn(Map.of("id", "pout_1" + user, "status", "processed"));
        call("/wallet/withdrawals", Map.of("amountMinor", 300_00, "vpa", "me@okbank"))
                .andExpect(status().isCreated()).andExpect(jsonPath("$.status").value("PAID"));
        assertEquals(70000, balance());
    }

    @Test
    void rejectedWithdrawalIsRefunded() throws Exception {
        when(gateway.createPayout(anyString(), anyLong(), anyString(), anyString()))
                .thenThrow(HttpClientErrorException.create(HttpStatus.BAD_REQUEST, "Bad Request", null, "{\"error\":{\"description\":\"invalid vpa\"}}".getBytes(), null));
        call("/wallet/withdrawals", Map.of("amountMinor", 300_00, "vpa", "nobody@okbank"))
                .andExpect(jsonPath("$.status").value("FAILED"));
        assertEquals(100000, balance());
    }

    @Test
    void timedOutWithdrawalStaysPendingThenReconciles() throws Exception {
        when(gateway.createPayout(anyString(), anyLong(), anyString(), anyString()))
                .thenThrow(new ResourceAccessException("read timed out"))
                .thenReturn(Map.of("id", "pout_2" + user, "status", "processing"));
        String id = id(call("/wallet/withdrawals", Map.of("amountMinor", 300_00, "vpa", "me@okbank"))
                .andExpect(jsonPath("$.status").value("PENDING")), "withdrawalId");
        assertEquals(70000, balance()); // unknown outcome: not refunded, can't be spent offline

        // Retry reuses the same id as the idempotency key, so Razorpay can't pay twice.
        call("/wallet/withdrawals/" + id + "/refresh", null).andExpect(jsonPath("$.status").value("PENDING"));
        verify(gateway, times(2)).createPayout(eq(id), anyLong(), anyString(), anyString());

        when(gateway.getPayout("pout_2" + user)).thenReturn(Map.of("id", "pout_2" + user, "status", "reversed"));
        call("/wallet/withdrawals/" + id + "/refresh", null).andExpect(jsonPath("$.status").value("FAILED"));
        call("/wallet/withdrawals/" + id + "/refresh", null).andExpect(jsonPath("$.status").value("FAILED"));
        assertEquals(100000, balance()); // refunded exactly once
    }

    @Test
    void cannotWithdrawMoreThanBalanceOrToBadUpiId() throws Exception {
        call("/wallet/withdrawals", Map.of("amountMinor", 2000_00, "vpa", "me@okbank"))
                .andExpect(status().isConflict()).andExpect(jsonPath("$.error").value("INSUFFICIENT_FUNDS"));
        call("/wallet/withdrawals", Map.of("amountMinor", 100_00, "vpa", "not-a-upi-id"))
                .andExpect(status().isBadRequest());
        verify(gateway, never()).createPayout(anyString(), anyLong(), anyString(), anyString());
        assertEquals(100000, balance());
    }

    private ResultActions call(String path, Object body) throws Exception {
        var req = post("/api/v1" + path).header("Authorization", "Bearer " + token);
        if (body != null) req.contentType(MediaType.APPLICATION_JSON).content(json.writeValueAsString(body));
        return mvc.perform(req);
    }

    private ResultActions webhook(String body, String signature) throws Exception {
        return mvc.perform(post("/api/v1/webhooks/razorpay").header("X-Razorpay-Signature", signature)
                .contentType(MediaType.APPLICATION_JSON).content(body));
    }

    private String id(ResultActions r, String field) throws Exception {
        return json.readValue(r.andReturn().getResponse().getContentAsString(), Map.class).get(field).toString();
    }

    private long balance() {
        return jdbc.sql("SELECT balance_minor FROM accounts WHERE username = ?").param(user).query(Long.class).single();
    }
}
