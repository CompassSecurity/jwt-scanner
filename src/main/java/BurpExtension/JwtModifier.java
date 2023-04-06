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
        return Base64.getUrlEncoder().withoutPadding().encodeToString(input.getBytes(StandardCharsets.UTF_8));
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
        JSONObject header = new JSONObject(decodeBase64Url(jwtParts[0]));
        JSONObject claim = new JSONObject(decodeBase64Url(jwtParts[1]));


        return createJwtFromJson(header, claim, dummyKey);
    }

    public String algNone(String jwt) {
        String[] jwtParts = jwt.split("\\.");
        JSONObject header = new JSONObject(decodeBase64Url(jwtParts[0]));

        header.put("alg", "none");
        return encodeBase64Url(header.toString()) + '.' + jwtParts[1] + '.';
    }

    public String emptyPassword(String jwt){
        String[] jwtParts = jwt.split("\\.");
        // Change this to empty password.
        String key = dummyKey.toString();
        return createJwtFromString(jwtParts[0],jwtParts[1],key);
    }

    private String createJwtFromString(String header, String claim, String key) {
        /* JWS Signing Input (RFC)
        The input to the digital signature or MAC computation.  Its value
        is ASCII(BASE64URL(UTF8(JWS Protected Header)) || '.' ||
        BASE64URL(JWS Payload)). */
        // Maybe add a valid check if it is already encoded.
        if (!header.startsWith("ey")) {
            String encodedHeader = encodeBase64Url(header);
            String encodedClaim = encodeBase64Url(claim);
        }

        String combined = header + "." + claim;
        String signature = createHmacSha256Signature(combined, key);
        return combined + "." + signature;
    }

    private static String createHmacSha256Signature(String input, String secret) {
        SecretKeySpec secretKeySpec = new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), "HmacSHA256");
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(secretKeySpec);

            byte[] hmacBytes = mac.doFinal(input.getBytes());
            return hmacBytes.toString();

        } catch (Exception e) {
            return input;
        }

    }

    public String calcHmacSha256(byte[] secretKey, byte[] message) {
        byte[] hmacSha256 = null;
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            SecretKeySpec secretKeySpec = new SecretKeySpec(secretKey, "HmacSHA256");
            mac.init(secretKeySpec);
            hmacSha256 = mac.doFinal(message);
        } catch (Exception e) {
            api.logging().logToError("Exception during " + "HmacSHA256" + ": " + e.getMessage());
        }
        return hmacSha256.toString();
    }


    private String createJwtFromJson(JSONObject headerJson, JSONObject claimsJson, SecretKey key){

        Map<String, Object> headerMap = headerJson.toMap();
        Map<String, Object> payloadMap = claimsJson.toMap();

        try {
            String newJwt = Jwts.builder()
                    .setHeader(headerMap)
                    .setClaims(payloadMap)
                    .signWith(key, SignatureAlgorithm.HS256)
                    .compact();
            return newJwt;
        } catch(JwtException ex) {
            api.logging().logToError("Some error while building the JWT: " + ex);
            return null;
        }
    }
}
