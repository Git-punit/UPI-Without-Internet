package com.upioffline.backend;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.*;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPublicKeySpec;

@SpringBootApplication
public class BackendApplication {

    public static void main(String[] args) {
        SpringApplication.run(BackendApplication.class, args);
    }

    /**
     * Key that senders encrypt packets to. Senders cache the public half for offline use, so it must survive
     * restarts: it is created once and then loaded from {@code upi.key-file}.
     */
    // shortcut: private key in a plain file (owner-only permissions); move to a keystore/HSM/KMS before real use.
    @Bean
    KeyPair backendKeyPair(@Value("${upi.key-file}") Path keyFile) throws GeneralSecurityException, IOException {
        KeyFactory rsa = KeyFactory.getInstance("RSA");
        if (Files.exists(keyFile)) {
            RSAPrivateCrtKey priv = (RSAPrivateCrtKey) rsa.generatePrivate(new PKCS8EncodedKeySpec(Files.readAllBytes(keyFile)));
            PublicKey pub = rsa.generatePublic(new RSAPublicKeySpec(priv.getModulus(), priv.getPublicExponent()));
            return new KeyPair(pub, priv);
        }
        KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
        gen.initialize(3072);
        KeyPair pair = gen.generateKeyPair();
        if (keyFile.getParent() != null) Files.createDirectories(keyFile.getParent());
        Path tmp = Files.createTempFile(keyFile.toAbsolutePath().getParent(), "key", ".tmp",
                PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")));
        Files.write(tmp, pair.getPrivate().getEncoded());
        Files.move(tmp, keyFile, StandardCopyOption.ATOMIC_MOVE);
        return pair;
    }
}
