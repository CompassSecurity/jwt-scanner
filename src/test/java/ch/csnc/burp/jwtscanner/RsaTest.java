package ch.csnc.burp.jwtscanner;

import org.junit.jupiter.api.Test;

import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPublicKey;
import java.util.UUID;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

public class RsaTest {

    @Test
    void testStoreAndRetrievePublicKeyOfJwk() throws Exception {
        var keyPairGen = KeyPairGenerator.getInstance("RSA");
        keyPairGen.initialize(2048);
        var keyPair = keyPairGen.generateKeyPair();
        var publicKey = (RSAPublicKey) keyPair.getPublic();
        var jwk = new Jwk(UUID.randomUUID().toString(), publicKey);
        Rsa.storePubicKeyOfJwk(jwk);
        var retrievedPublicKey = Rsa.retrievePublicKeyOfJwk().orElseThrow();
        assertThat(publicKey, equalTo(retrievedPublicKey));
    }

    @Test
    void testPublicKeyToPen() throws Exception {
        var keyPairGen = KeyPairGenerator.getInstance("RSA");
        keyPairGen.initialize(2048);
        var keyPair = keyPairGen.generateKeyPair();
        var publicKey = keyPair.getPublic();
        assertDoesNotThrow(() -> Rsa.publicKeyToPem(publicKey));
    }

}
