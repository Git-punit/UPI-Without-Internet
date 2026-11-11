package com.upioffline.backend;

import com.upioffline.protocol.PaymentInstruction;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.sql.Timestamp;

/** Mock payment processor: moves mock balances between user accounts. */
@Service
public class Ledger {

    private final JdbcClient jdbc;

    public Ledger(JdbcClient jdbc) {
        this.jdbc = jdbc;
    }

    @Transactional
    public void registerUser(String username, String passwordHash, long startingBalanceMinor) {
        jdbc.sql("INSERT INTO users (username, password_hash) VALUES (?, ?)").params(username, passwordHash).update();
        jdbc.sql("INSERT INTO accounts (username, balance_minor) VALUES (?, ?)").params(username, startingBalanceMinor).update();
    }

    /** Credits a confirmed UPI top-up. Returns false if it was already credited (webhook and refresh both race here). */
    @Transactional
    public boolean creditTopup(String topupId) {
        if (jdbc.sql("UPDATE topups SET status = 'PAID' WHERE topup_id = ? AND status = 'PENDING'").param(topupId).update() == 0)
            return false;
        jdbc.sql("""
                UPDATE accounts SET balance_minor = balance_minor + (SELECT amount_minor FROM topups WHERE topup_id = ?)
                WHERE username = (SELECT username FROM topups WHERE topup_id = ?)""").params(topupId, topupId).update();
        return true;
    }

    /** Debits first, so the money can't be spent offline while the payout is in flight. */
    @Transactional
    public void startWithdrawal(String withdrawalId, String username, long amountMinor, String vpa) {
        int debited = jdbc.sql("UPDATE accounts SET balance_minor = balance_minor - ? WHERE username = ? AND balance_minor >= ?")
                .params(amountMinor, username, amountMinor).update();
        if (debited == 0) throw new ApiException(org.springframework.http.HttpStatus.CONFLICT, "INSUFFICIENT_FUNDS", "wallet balance too low");
        jdbc.sql("INSERT INTO withdrawals (withdrawal_id, username, amount_minor, vpa, status) VALUES (?, ?, ?, ?, 'PENDING')")
                .params(withdrawalId, username, amountMinor, vpa).update();
    }

    /** Refunds a payout the gateway definitely did not make. Only once, however often it is reported. */
    @Transactional
    public void failWithdrawal(String withdrawalId, String reason) {
        int changed = jdbc.sql("UPDATE withdrawals SET status = 'FAILED', failure_reason = ? WHERE withdrawal_id = ? AND status = 'PENDING'")
                .params(reason.length() > 255 ? reason.substring(0, 255) : reason, withdrawalId).update();
        if (changed == 1) jdbc.sql("""
                UPDATE accounts SET balance_minor = balance_minor + (SELECT amount_minor FROM withdrawals WHERE withdrawal_id = ?)
                WHERE username = (SELECT username FROM withdrawals WHERE withdrawal_id = ?)""").params(withdrawalId, withdrawalId).update();
    }

    /**
     * Records the transaction and settles it in one DB transaction. Throws DuplicateKeyException if the id was
     * already used (the insert comes first, so a duplicate never reaches the debit).
     */
    @Transactional
    public void settle(PaymentInstruction ins, String payloadHash, String senderUser, String receiverUser) {
        jdbc.sql("""
                        INSERT INTO transactions (transaction_id, sender_id, receiver_id, amount_minor, currency,
                                                  payload_hash, status, created_at, expires_at)
                        VALUES (?, ?, ?, ?, ?, ?, 'PROCESSING', ?, ?)""")
                .params(ins.transactionId(), ins.senderId(), ins.receiverId(), ins.amountMinor(), ins.currency(),
                        payloadHash, Timestamp.from(ins.createdAt()), Timestamp.from(ins.expiresAt()))
                .update();

        // Conditional debit is the double-spend guard: two offline packets that together exceed the balance
        // both verify, but only the ones that fit when they arrive succeed.
        int debited = jdbc.sql("UPDATE accounts SET balance_minor = balance_minor - ? WHERE username = ? AND balance_minor >= ?")
                .params(ins.amountMinor(), senderUser, ins.amountMinor()).update();
        if (debited == 1) {
            int credited = jdbc.sql("UPDATE accounts SET balance_minor = balance_minor + ? WHERE username = ?")
                    .params(ins.amountMinor(), receiverUser).update();
            if (credited != 1) throw new IllegalStateException("receiver account missing"); // rolls back the debit
        }
        jdbc.sql("UPDATE transactions SET status = ?, failure_reason = ? WHERE transaction_id = ?")
                .params(debited == 1 ? "SUCCESS" : "FAILED", debited == 1 ? null : "INSUFFICIENT_FUNDS", ins.transactionId())
                .update();
    }
}
