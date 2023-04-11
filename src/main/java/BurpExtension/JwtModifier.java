package BurpExtension;
import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import burp.api.montoya.MontoyaApi;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Map;

import org.json.*;

public class JwtModifier {
    private final MontoyaApi api;
    private final SecretKey dummyKey = Keys.secretKeyFor(SignatureAlgorithm.HS256);

    JwtModifier (MontoyaApi api){
        this.api = api;
    }
    public void decode(String jwt){
        String[] jwtParts = jwt.split("\\.");

        // Decode JWT header
        String header = jwtParts[0];
        String decodedHeader = decodeBase64Url(header);
        api.logging().logToOutput("Decoded header: " + decodedHeader);

        // Decode JWT payload
        String payload = jwtParts[1];
        String decodedClaim = decodeBase64Url(payload);
        api.logging().logToOutput("Decoded claim: " + decodedClaim);

        // Decode JWT signature (this step is optional as the signature is not human-readable)
        String signature = jwtParts[2];
        String decodedSignature = decodeBase64Url(signature);
        api.logging().logToOutput("Decoded signature: " + decodedSignature);
    }

    private static String decodeBase64Url(String base64Url) {
        Base64.Decoder decoder = Base64.getUrlDecoder();
        byte[] decodedBytes = decoder.decode(base64Url);
        return new String(decodedBytes, StandardCharsets.UTF_8);
    }

    private static String encodeBase64Url(String input) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(input.getBytes());
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
        // TODO: Change this to empty password.
        String key = "\n";
        String combined = jwtParts[0] + '.' + jwtParts[1];
        return combined + '.' + createHmacSha256EmptySignature(combined);
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
}
