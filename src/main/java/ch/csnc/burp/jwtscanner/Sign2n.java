package ch.csnc.burp.jwtscanner;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.List;

import static ch.csnc.burp.jwtscanner.Base64.base64UrlDecoder;

public class Sign2n {

    /**
     * Based on
     * <ul>
     * <li><a href="https://github.com/silentsignal/rsa_sign2n/blob/release/standalone/jwt_forgery.py">jwt_forgery.py</a></li>
     * <li><a href="https://blog.ploetzli.ch/2018/calculating-an-rsa-public-key-from-two-signatures/">https://blog.ploetzli.ch/2018/calculating-an-rsa-public-key-from-two-signatures/</a></li>
     * </ul>
     */
    public static List<RSAPublicKey> forgePublicKeys(Jwt jwt1, Jwt jwt2) {
        try {
            var alg1 = jwt1.getAlg().orElse(null);
            var alg2 = jwt2.getAlg().orElse(null);

            if (alg1 == null || alg2 == null) {
                return List.of();
            }

            if (!alg1.equals(alg2)) {
                return List.of();
            }

            if (!alg1.startsWith("RS")) {
                return List.of();
            }

            if (!alg1.equals("RS256")) {
                return List.of();
            }

            var sig1Bytes = base64UrlDecoder.decode(jwt1.encodedSignature());
            var sig2Bytes = base64UrlDecoder.decode(jwt2.encodedSignature());

            if (sig1Bytes.length != sig2Bytes.length) {
                return List.of();
            }

            var sig1 = new BigInteger(1, sig1Bytes);
            var sig2 = new BigInteger(1, sig2Bytes);

            var input1 = "%s.%s".formatted(jwt1.encodedHeader(), jwt1.encodedPayload());
            var input2 = "%s.%s".formatted(jwt2.encodedHeader(), jwt2.encodedPayload());

            var padded1 = hashPad(sig1Bytes.length, input1.getBytes(StandardCharsets.UTF_8), "SHA-256");
            var padded2 = hashPad(sig2Bytes.length, input2.getBytes(StandardCharsets.UTF_8), "SHA-256");

            var m1 = new BigInteger(1, hexStringToByteArray(padded1));
            var m2 = new BigInteger(1, hexStringToByteArray(padded2));

            var publicKeys = new ArrayList<RSAPublicKey>();

            var gmp = new Gmp();

            for (var e : List.of(3, 65537)) {
                var nk =
                        gmp.gcd(
                                gmp.sub(gmp.pow(sig1.toString(), String.valueOf(e)), m1.toString()),
                                gmp.sub(gmp.pow(sig2.toString(), String.valueOf(e)), m2.toString()));
                // warning gcd my not return n, but n * k for small k.
                for (var k = 1; k <= 100; k++) {
                    var n = new BigInteger(gmp.cdiv(nk, String.valueOf(k)));
                    if (BigInteger.ZERO.equals(n)) {
                        break;
                    }
                    if (new BigInteger(gmp.powm(sig1.toString(), String.valueOf(e), n.toString())).equals(m1)) {
                        publicKeys.add(Rsa.publicKeyOf(n, BigInteger.valueOf(e)));
                    }
                }
            }

            return List.copyOf(publicKeys);
        } catch (Exception exc) {
            JwtScannerExtension.logging().logToError(exc);
            throw new RuntimeException(exc);
        }
    }

    private static String hashPad(int sizeBytes, byte[] data, String hashAlgorithm) {
        try {
            MessageDigest digest = MessageDigest.getInstance(hashAlgorithm);
            byte[] hash = digest.digest(data);
            StringBuilder hex = new StringBuilder();
            for (byte b : hash) {
                hex.append(String.format("%02X", b));
            }
            return pkcs1Padding(sizeBytes, hex.toString(), hashAlgorithm);
        } catch (Exception exc) {
            JwtScannerExtension.logging().logToError(exc);
            throw new RuntimeException(exc);
        }
    }

    private static String pkcs1Padding(int sizeBytes, String hex, String hashAlgorithm) {
        String oid = "";
        if ("SHA-256".equals(hashAlgorithm)) {
            oid = "608648016503040201";
        } else {
            throw new IllegalArgumentException("Unsupported hash algorithm: " + hashAlgorithm);
        }

        String result = "06" + String.format("%02X", oid.length() / 2) + oid + "05" + "00";
        result = "30" + String.format("%02X", result.length() / 2) + result;
        result = result + "04" + String.format("%02X", hex.length() / 2) + hex;
        result = "30" + String.format("%02X", result.length() / 2) + result;
        result = "0001" + "ff".repeat(sizeBytes - 3 - result.length() / 2) + "00" + result;

        return result;
    }

    private static byte[] hexStringToByteArray(String hex) {
        var length = hex.length();
        var data = new byte[length / 2];

        for (int i = 0; i < length; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4) + Character.digit(hex.charAt(i + 1), 16));
        }
        return data;
    }

}
