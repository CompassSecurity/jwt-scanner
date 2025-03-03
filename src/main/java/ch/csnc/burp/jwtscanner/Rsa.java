package ch.csnc.burp.jwtscanner;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPublicKeySpec;

import static ch.csnc.burp.jwtscanner.Base64.base64EncoderWithPadding;

public abstract class Rsa {

    public static KeyPair generateKeyPair() {
        try {
            var keyPairGen = KeyPairGenerator.getInstance("RSA");
            keyPairGen.initialize(2048);
            return keyPairGen.generateKeyPair();
        } catch (Exception exc) {
            JwtScannerExtension.logging().logToError(exc);
            throw new RuntimeException(exc);
        }
    }

    public static RSAPublicKey publicKeyOf(Jwk jwk) {
        try {
            var modulus = jwk.modulusBigInt();
            var exponent = jwk.exponentBigInt();
            return publicKeyOf(modulus, exponent);
        } catch (Exception exc) {
            JwtScannerExtension.logging().logToError(exc);
            throw new RuntimeException(exc);
        }
    }

    public static RSAPublicKey publicKeyOf(BigInteger n, BigInteger e) {
        try {
            var spec = new RSAPublicKeySpec(n, e);
            var keyFactory = KeyFactory.getInstance("RSA");
            return (RSAPublicKey) keyFactory.generatePublic(spec);
        } catch (Exception exc) {
            JwtScannerExtension.logging().logToError(exc);
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
