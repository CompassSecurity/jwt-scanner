package ch.csnc.burp.jwtscanner;

import com.google.gson.JsonElement;
import com.google.gson.JsonSerializationContext;
import com.google.gson.JsonSerializer;

import java.lang.reflect.Type;
import java.security.interfaces.RSAPublicKey;
import java.util.LinkedHashMap;

import static ch.csnc.burp.jwtscanner.Base64.base64UrlEncoderNoPadding;
import static ch.csnc.burp.jwtscanner.Gson.gson;

public class Jwk {

    private final LinkedHashMap<String, Object> keyValues = new LinkedHashMap<>();

    public Jwk(String kid, RSAPublicKey publicKey) {
        keyValues.put("kid", kid);
        keyValues.put("kty", "RSA");
        keyValues.put("e", base64UrlEncoderNoPadding.encodeToString(publicKey.getPublicExponent().toByteArray()));
        keyValues.put("n", base64UrlEncoderNoPadding.encodeToString(publicKey.getModulus().toByteArray()));
    }

    public static class JwkJsonSerializer implements JsonSerializer<Jwk> {

        @Override
        public JsonElement serialize(Jwk src, Type typeOfSrc, JsonSerializationContext context) {
            return gson.toJsonTree(src.keyValues);
        }

    }

}
