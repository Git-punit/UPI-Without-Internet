package com.upioffline.backend;

import com.upioffline.protocol.Envelope;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

import static com.upioffline.backend.AuthController.USER_ATTR;

@RestController
@RequestMapping("/api/v1/transactions")
public class TransactionController {

    private final TransactionService transactions;

    public TransactionController(TransactionService transactions) {
        this.transactions = transactions;
    }

    /**
     * Submit a packet carried over Bluetooth: by the receiver, the sender, or any relaying phone. For the sender
     * or receiver: 201 when first settled, 200 when the same packet comes again. For a relay: 202, no details. Body status is SUCCESS or FAILED: the mock processor answers immediately.
     */
    @PostMapping
    public ResponseEntity<?> submit(@RequestAttribute(USER_ATTR) String username, @RequestBody Envelope envelope) {
        TransactionService.Submission s = transactions.submit(envelope, username);
        // A relaying stranger only learns it was delivered: no amount, no outcome.
        if (!s.party()) return ResponseEntity.accepted().body(Map.of("transactionId", s.transaction().transactionId(), "delivered", true));
        return ResponseEntity.status(s.created() ? HttpStatus.CREATED : HttpStatus.OK).body(s.transaction());
    }

    /** Your transactions, as sender or receiver, newest first. */
    @GetMapping
    public List<TransactionService.TransactionView> history(@RequestAttribute(USER_ATTR) String username) {
        return transactions.history(username);
    }

    @GetMapping("/{id}")
    public TransactionService.TransactionView get(@RequestAttribute(USER_ATTR) String username, @PathVariable String id) {
        return transactions.findVisible(id, username)
                .orElseThrow(() -> new ApiException(HttpStatus.NOT_FOUND, "TRANSACTION_NOT_FOUND", "no such transaction"));
    }
}
