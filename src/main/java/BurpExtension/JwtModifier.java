package BurpExtension;
import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import burp.api.montoya.MontoyaApi;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import org.json.*;

public class JwtModifier {
    private final MontoyaApi api;
    private SecretKey dummyKey = Keys.secretKeyFor(SignatureAlgorithm.HS256);

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

    public boolean isJwtNotExpired(String jwt) {
        String[] jwtParts = jwt.split("\\.");
        String payload = jwtParts[1];
        String decodedClaim = decodeBase64Url(payload);
        JSONObject claim = new JSONObject(decodedClaim);
        long expValue = claim.getLong("exp");
        long currentTime = System.currentTimeMillis()/1000;
        return expValue > currentTime;
    }

    public String modifyClaim(String jwt){


        return "null";
    }
}
