package com.upioffline.backend;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

import static com.upioffline.backend.AuthController.USER_ATTR;

@RestController
@RequestMapping("/api/v1")
public class WalletController {

    public record TopupRequest(long amountMinor) {
    }

    public record WithdrawRequest(long amountMinor, String vpa) {
    }

    private final WalletService wallet;

    public WalletController(WalletService wallet) {
        this.wallet = wallet;
    }

    @GetMapping("/wallet")
    public Map<String, Object> get(@RequestAttribute(USER_ATTR) String username) {
        return wallet.wallet(username);
    }

    /** Returns a Razorpay link; the wallet is credited only once Razorpay confirms the UPI payment. */
    @PostMapping("/wallet/topups")
    @ResponseStatus(HttpStatus.CREATED)
    public WalletService.Topup topup(@RequestAttribute(USER_ATTR) String username, @RequestBody TopupRequest req) {
        return wallet.createTopup(username, req.amountMinor());
    }

    @PostMapping("/wallet/topups/{id}/refresh")
    public WalletService.Topup refreshTopup(@RequestAttribute(USER_ATTR) String username, @PathVariable String id) {
        return wallet.refreshTopup(username, id);
    }

    /** Pays out to a UPI ID. Status PENDING means not confirmed yet: refresh later, it will never be paid twice. */
    @PostMapping("/wallet/withdrawals")
    @ResponseStatus(HttpStatus.CREATED)
    public WalletService.Withdrawal withdraw(@RequestAttribute(USER_ATTR) String username, @RequestBody WithdrawRequest req) {
        return wallet.withdraw(username, req.amountMinor(), req.vpa());
    }

    @PostMapping("/wallet/withdrawals/{id}/refresh")
    public WalletService.Withdrawal refreshWithdrawal(@RequestAttribute(USER_ATTR) String username, @PathVariable String id) {
        return wallet.refreshWithdrawal(username, id);
    }

    /** Public, but only acted on when Razorpay's signature verifies. Point Razorpay's webhook settings here. */
    @PostMapping("/webhooks/razorpay")
    public Map<String, Boolean> webhook(@RequestBody String body, @RequestHeader(value = "X-Razorpay-Signature", required = false) String signature) {
        wallet.webhook(body, signature);
        return Map.of("ok", true);
    }
}
