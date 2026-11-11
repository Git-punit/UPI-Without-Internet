CREATE TABLE IF NOT EXISTS users (
    username      VARCHAR(64)  PRIMARY KEY,
    password_hash VARCHAR(100) NOT NULL, -- BCrypt
    created_at    TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Login tokens. Only a SHA-256 of the token is stored, so a database leak does not leak live sessions.
CREATE TABLE IF NOT EXISTS sessions (
    token_hash VARCHAR(64) PRIMARY KEY,
    username   VARCHAR(64) NOT NULL REFERENCES users(username),
    expires_at TIMESTAMP   NOT NULL
);

-- Mock balances only. A real deployment asks the bank/PSP for funds; it never keeps balances here.
CREATE TABLE IF NOT EXISTS accounts (
    username      VARCHAR(64) PRIMARY KEY REFERENCES users(username),
    balance_minor BIGINT      NOT NULL CHECK (balance_minor >= 0)
);

CREATE TABLE IF NOT EXISTS devices (
    device_id  VARCHAR(64)   PRIMARY KEY,
    username   VARCHAR(64)   NOT NULL REFERENCES users(username),
    public_key VARCHAR(2048) NOT NULL,
    created_at TIMESTAMP     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    revoked_at TIMESTAMP -- set when the phone is lost; its packets are then refused
);

-- The primary key is the idempotency guarantee: a transaction id can be settled at most once.
CREATE TABLE IF NOT EXISTS transactions (
    transaction_id VARCHAR(36) PRIMARY KEY,
    sender_id      VARCHAR(64) NOT NULL REFERENCES devices(device_id),
    receiver_id    VARCHAR(64) NOT NULL REFERENCES devices(device_id),
    amount_minor   BIGINT      NOT NULL,
    currency       VARCHAR(3)  NOT NULL,
    payload_hash   VARCHAR(64) NOT NULL,
    status         VARCHAR(16) NOT NULL,
    failure_reason VARCHAR(64),
    created_at     TIMESTAMP   NOT NULL,
    expires_at     TIMESTAMP   NOT NULL,
    submitted_at   TIMESTAMP   NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Money in: a real UPI payment through Razorpay credits the wallet, exactly once.
CREATE TABLE IF NOT EXISTS topups (
    topup_id     VARCHAR(36)  PRIMARY KEY,
    username     VARCHAR(64)  NOT NULL REFERENCES users(username),
    amount_minor BIGINT       NOT NULL,
    link_id      VARCHAR(64)  UNIQUE,
    payment_url  VARCHAR(512),
    status       VARCHAR(16)  NOT NULL, -- PENDING, PAID, EXPIRED
    created_at   TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Money out: a payout to the user's UPI ID. Debited first; refunded only if the gateway says it failed.
CREATE TABLE IF NOT EXISTS withdrawals (
    withdrawal_id  VARCHAR(36)  PRIMARY KEY,
    username       VARCHAR(64)  NOT NULL REFERENCES users(username),
    amount_minor   BIGINT       NOT NULL,
    vpa            VARCHAR(320) NOT NULL,
    payout_id      VARCHAR(64)  UNIQUE,
    status         VARCHAR(16)  NOT NULL, -- PENDING (incl. unknown outcome), PAID, FAILED
    failure_reason VARCHAR(255),
    created_at     TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP
);
