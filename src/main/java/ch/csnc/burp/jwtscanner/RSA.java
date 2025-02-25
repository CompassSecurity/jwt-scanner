package ch.csnc.burp.jwtscanner;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public abstract class RSA {

    public static KeyPair getOrGenerateKeyPair() {
        try {
            var privateKeyEncoded = JwtScannerExtension.apiAdapter().persistence().extensionData().getByteArray("privatekey");
            var publicKeyEncoded = JwtScannerExtension.apiAdapter().persistence().extensionData().getByteArray("publickey");
            if (privateKeyEncoded == null || publicKeyEncoded == null) {
                var keyPairGen = KeyPairGenerator.getInstance("RSA");
                keyPairGen.initialize(2048);
                var keyPair = keyPairGen.generateKeyPair();
                privateKeyEncoded = keyPair.getPrivate().getEncoded();
                publicKeyEncoded = keyPair.getPublic().getEncoded();
                JwtScannerExtension.apiAdapter().persistence().extensionData().setByteArray("privatekey", privateKeyEncoded);
                JwtScannerExtension.apiAdapter().persistence().extensionData().setByteArray("publickey", publicKeyEncoded);
            }
            var keyFactory = KeyFactory.getInstance("RSA");
            var privateKey = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(privateKeyEncoded));
            var publicKey = (RSAPublicKey) keyFactory.generatePublic(new X509EncodedKeySpec(publicKeyEncoded));
            return new KeyPair(publicKey, privateKey);
        } catch (Exception exc) {
            throw new RuntimeException(exc);
        }
    }

}
