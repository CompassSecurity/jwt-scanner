package ch.csnc.burp.jwtscanner;

import org.junit.jupiter.api.Test;

import java.security.KeyPairGenerator;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

public class RsaTest {

    @Test
    void testPublicKeyToPen() throws Exception {
        var keyPairGen = KeyPairGenerator.getInstance("RSA");
        keyPairGen.initialize(2048);
        var keyPair = keyPairGen.generateKeyPair();
        var publicKey = keyPair.getPublic();
        assertDoesNotThrow(() -> Rsa.publicKeyToPem(publicKey));
    }

}
