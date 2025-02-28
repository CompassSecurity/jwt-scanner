package ch.csnc.burp.jwtscanner;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Optional;

import static ch.csnc.burp.jwtscanner.Base64.base64EncoderWithPadding;

public abstract class Rsa {

    public static KeyPair getOrGenerateKeyPair() {
        try {
            var privateKeyEncoded = JwtScannerExtension.apiAdapter().persistence().extensionData().getByteArray("selfSignedPrivateKey");
            var publicKeyEncoded = JwtScannerExtension.apiAdapter().persistence().extensionData().getByteArray("selfSignedPublicKey");
            if (privateKeyEncoded == null || publicKeyEncoded == null) {
                var keyPairGen = KeyPairGenerator.getInstance("RSA");
                keyPairGen.initialize(2048);
                var keyPair = keyPairGen.generateKeyPair();
                privateKeyEncoded = keyPair.getPrivate().getEncoded();
                publicKeyEncoded = keyPair.getPublic().getEncoded();
                JwtScannerExtension.apiAdapter().persistence().extensionData().setByteArray("selfSignedPrivateKey", privateKeyEncoded);
                JwtScannerExtension.apiAdapter().persistence().extensionData().setByteArray("selfSignedPublicKey", publicKeyEncoded);
            }
            var keyFactory = KeyFactory.getInstance("RSA");
            var privateKey = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(privateKeyEncoded));
            var publicKey = (RSAPublicKey) keyFactory.generatePublic(new X509EncodedKeySpec(publicKeyEncoded));
            return new KeyPair(publicKey, privateKey);
        } catch (Exception exc) {
            JwtScannerExtension.apiAdapter().logging().logToError(exc);
            throw new RuntimeException(exc);
        }
    }

    public static void storePubicKeyOfJwk(Jwk jwk) {
        try {
            var modulus = jwk.modulusBigInt();
            var exponent = jwk.exponentBigInt();
            var spec = new RSAPublicKeySpec(modulus, exponent);
            var keyFactory = KeyFactory.getInstance("RSA");
            var publicKey = keyFactory.generatePublic(spec);
            JwtScannerExtension.apiAdapter().persistence().extensionData().setByteArray("jwkPublicKey", publicKey.getEncoded());
        } catch (Exception exc) {
            JwtScannerExtension.apiAdapter().logging().logToError(exc);
            throw new RuntimeException(exc);
        }
    }

    public static Optional<RSAPublicKey> retrievePublicKeyOfJwk() {
        try {
            var keyFactory = KeyFactory.getInstance("RSA");
            var publicKeyEncoded = JwtScannerExtension.apiAdapter().persistence().extensionData().getByteArray("jwkPublicKey");
            if (publicKeyEncoded == null) {
                return Optional.empty();
            }
            var publicKey = keyFactory.generatePublic(new X509EncodedKeySpec(publicKeyEncoded));
            return Optional.of((RSAPublicKey) publicKey);
        } catch (Exception exc) {
            JwtScannerExtension.apiAdapter().logging().logToError(exc);
            throw new RuntimeException(exc);
        }
    }

    public static String publicKeyToPem(PublicKey publicKey) {
        var bytes = publicKey.getEncoded();
        var base64 = base64EncoderWithPadding.encodeToString(bytes);
        var pemBuilder = new StringBuilder();
        pemBuilder.append("-----BEGIN PUBLIC KEY-----\n");
        for (int start = 0; start < base64.length(); start += 64) {
            int end = Math.min(start + 64, base64.length());
            pemBuilder.append(base64, start, end).append("\n");
        }
        pemBuilder.append("-----END PUBLIC KEY-----\n");
        return pemBuilder.toString();
    }

}
