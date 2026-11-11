package com.upioffline.backend;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.KeyPair;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

class BackendKeyTest {

    @Test
    void keySurvivesRestartAndIsOwnerOnly(@TempDir Path dir) throws Exception {
        Path file = dir.resolve("keys/backend-key.der");
        KeyPair first = new BackendApplication().backendKeyPair(file);
        KeyPair afterRestart = new BackendApplication().backendKeyPair(file);
        assertArrayEquals(first.getPublic().getEncoded(), afterRestart.getPublic().getEncoded());
        assertArrayEquals(first.getPrivate().getEncoded(), afterRestart.getPrivate().getEncoded());
        assertEquals("rw-------", PosixFilePermissions.toString(Files.getPosixFilePermissions(file)));
    }
}
