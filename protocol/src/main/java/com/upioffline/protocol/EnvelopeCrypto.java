package com.upioffline.protocol;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.HexFormat;
import java.util.function.Function;

/**
 * Version 1: sign the canonical instruction with RSA-PSS (SHA-256), encrypt instruction + signature with a fresh
 * AES-256-GCM key, and wrap that key with RSA-OAEP (SHA-256) for the backend.
 */
public final class EnvelopeCrypto {

    private static final SecureRandom RANDOM = new SecureRandom();
    // Explicit params: Android's default MGF1 digest for OAEP is SHA-1, which would not interoperate.
    private static final OAEPParameterSpec OAEP = new OAEPParameterSpec(
            "SHA-256", "MGF1", MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT);
    private static final PSSParameterSpec PSS = new PSSParameterSpec(
            "SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1);
    private static final String RSA_OAEP = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding";
    private static final int NONCE_BYTES = 12;
    private static final int TAG_BITS = 128;

    private EnvelopeCrypto() {
    }

    public static Envelope seal(PaymentInstruction instruction, PrivateKey senderKey, PublicKey backendKey)
            throws GeneralSecurityException {
        byte[] canonical = instruction.canonicalBytes();
        byte[] signature = sign(canonical, senderKey);
        byte[] plaintext = ByteBuffer.allocate(4 + canonical.length + signature.length)
                .putInt(canonical.length).put(canonical).put(signature).array();

        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256, RANDOM);
        SecretKey aesKey = keyGen.generateKey();
        byte[] nonce = new byte[NONCE_BYTES];
        RANDOM.nextBytes(nonce); // fresh key per packet, so nonce reuse under one key cannot happen

        Cipher gcm = Cipher.getInstance("AES/GCM/NoPadding");
        gcm.init(Cipher.ENCRYPT_MODE, aesKey, new GCMParameterSpec(TAG_BITS, nonce));
        gcm.updateAAD(aad(instruction.transactionId(), instruction.senderId(), instruction.receiverId()));
        byte[] ciphertext = gcm.doFinal(plaintext);

        Cipher rsa = Cipher.getInstance(RSA_OAEP);
        rsa.init(Cipher.ENCRYPT_MODE, backendKey, OAEP);
        byte[] wrappedKey = rsa.doFinal(aesKey.getEncoded());

        Base64.Encoder b64 = Base64.getEncoder();
        return new Envelope(PaymentInstruction.VERSION, instruction.transactionId(), instruction.senderId(),
                instruction.receiverId(), b64.encodeToString(nonce), b64.encodeToString(wrappedKey),
                b64.encodeToString(ciphertext));
    }

    /**
     * Decrypts and checks integrity and the sender's signature. Does NOT check expiry, funds or duplicates;
     * that is the backend's job, using trusted server time.
     */
    public static PaymentInstruction open(Envelope envelope, PrivateKey backendKey,
                                          Function<String, PublicKey> senderKeys) throws InvalidEnvelopeException {
        byte[] canonical;
        byte[] signature;
        PaymentInstruction instruction;
        try {
            if (envelope.protocolVersion() != PaymentInstruction.VERSION)
                throw new InvalidEnvelopeException("unsupported protocol version");
            Base64.Decoder b64 = Base64.getDecoder();
            byte[] nonce = b64.decode(envelope.nonce());
            if (nonce.length != NONCE_BYTES) throw new InvalidEnvelopeException("bad nonce length");

            Cipher rsa = Cipher.getInstance(RSA_OAEP);
            rsa.init(Cipher.DECRYPT_MODE, backendKey, OAEP);
            byte[] keyBytes = rsa.doFinal(b64.decode(envelope.encryptedKey()));
            if (keyBytes.length != 32) throw new InvalidEnvelopeException("bad key length");

            Cipher gcm = Cipher.getInstance("AES/GCM/NoPadding");
            gcm.init(Cipher.DECRYPT_MODE, new SecretKeySpec(keyBytes, "AES"), new GCMParameterSpec(TAG_BITS, nonce));
            gcm.updateAAD(aad(envelope.transactionId(), envelope.senderId(), envelope.receiverId()));
            ByteBuffer plain = ByteBuffer.wrap(gcm.doFinal(b64.decode(envelope.ciphertext())));

            int len = plain.getInt();
            if (len < 0 || len > plain.remaining()) throw new InvalidEnvelopeException("bad length prefix");
            canonical = new byte[len];
            plain.get(canonical);
            signature = new byte[plain.remaining()];
            plain.get(signature);
            instruction = PaymentInstruction.fromCanonicalBytes(canonical);
        } catch (GeneralSecurityException | RuntimeException e) {
            throw new InvalidEnvelopeException("malformed or tampered envelope", e);
        }

        if (!instruction.transactionId().equals(envelope.transactionId())
                || !instruction.senderId().equals(envelope.senderId())
                || !instruction.receiverId().equals(envelope.receiverId()))
            throw new InvalidEnvelopeException("envelope header does not match instruction");

        PublicKey senderKey = senderKeys.apply(instruction.senderId());
        if (senderKey == null) throw new InvalidEnvelopeException("unknown sender");
        try {
            if (!verify(canonical, signature, senderKey)) throw new InvalidEnvelopeException("bad signature");
        } catch (GeneralSecurityException e) {
            throw new InvalidEnvelopeException("bad signature", e);
        }
        return instruction;
    }

    /** SHA-256 of the canonical instruction: same instruction re-sealed gives the same fingerprint. */
    public static String fingerprint(PaymentInstruction instruction) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(instruction.canonicalBytes()));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    public static String publicKeyToBase64(PublicKey key) {
        return Base64.getEncoder().encodeToString(key.getEncoded());
    }

    public static PublicKey publicKeyFromBase64(String x509Base64) throws GeneralSecurityException {
        try {
            return KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(Base64.getDecoder().decode(x509Base64)));
        } catch (IllegalArgumentException | NullPointerException e) {
            throw new GeneralSecurityException("invalid public key encoding", e);
        }
    }

    /**
     * What a device signs when it is enrolled, proving it holds the private key for the public key it registers
     * and binding that key to one user account.
     */
    public static byte[] registrationMessage(String deviceId, String username) {
        return ("upi-offline/register/v1|" + deviceId + "|" + username).getBytes(StandardCharsets.UTF_8);
    }

    public static byte[] sign(byte[] data, PrivateKey key) throws GeneralSecurityException {
        Signature s = pss();
        s.initSign(key, RANDOM);
        s.update(data);
        return s.sign();
    }

    public static boolean verify(byte[] data, byte[] signature, PublicKey key) throws GeneralSecurityException {
        Signature s = pss();
        s.initVerify(key);
        s.update(data);
        return s.verify(signature);
    }

    /**
     * Android (incl. Keystore keys) names it "SHA256withRSA/PSS", whose defaults are MGF1-SHA256 and a 32-byte salt.
     * The JDK only knows "RSASSA-PSS" with explicit parameters. Both produce the same signatures.
     */
    private static Signature pss() throws GeneralSecurityException {
        try {
            return Signature.getInstance("SHA256withRSA/PSS");
        } catch (NoSuchAlgorithmException e) {
            Signature s = Signature.getInstance("RSASSA-PSS");
            s.setParameter(PSS);
            return s;
        }
    }

    private static byte[] aad(String transactionId, String senderId, String receiverId) {
        return ("upi-offline/v1|" + transactionId + "|" + senderId + "|" + receiverId).getBytes(StandardCharsets.UTF_8);
    }
}
