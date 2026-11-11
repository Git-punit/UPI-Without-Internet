package com.upioffline.protocol;

/**
 * The packet that travels sender → receiver (Bluetooth) → backend (HTTPS). Binary fields are Base64.
 *
 * <p>Only routing ids are visible. Amount, expiry and the sender's signature live inside {@code ciphertext},
 * which only the backend can decrypt. The visible ids are bound to the ciphertext as AES-GCM associated data,
 * so changing any of them makes decryption fail. Algorithms are fixed by {@code protocolVersion}.
 */
public record Envelope(int protocolVersion, String transactionId, String senderId, String receiverId,
                       String nonce, String encryptedKey, String ciphertext) {
}
