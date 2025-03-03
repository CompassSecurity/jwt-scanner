package ch.csnc.burp.jwtscanner;

import org.junit.jupiter.api.Test;

import java.security.interfaces.RSAPublicKey;
import java.util.UUID;

import static ch.csnc.burp.jwtscanner.Gson.gson;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.startsWith;

public class JwkTest {

    @Test
    void testSerializeToJson() {
        var keyPair = Rsa.generateKeyPair();
        var kid = UUID.randomUUID().toString();
        var jwk = new Jwk(kid, (RSAPublicKey) keyPair.getPublic());
        var json = gson.toJson(jwk);
        assertThat(json, startsWith("{\"kid\":"));
    }

}
