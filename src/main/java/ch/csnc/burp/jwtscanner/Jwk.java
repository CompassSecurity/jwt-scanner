package ch.csnc.burp.jwtscanner;

import com.google.gson.*;

import java.lang.reflect.Type;
import java.math.BigInteger;
import java.security.interfaces.RSAPublicKey;
import java.util.LinkedHashMap;
import java.util.Map;

import static ch.csnc.burp.jwtscanner.Base64.base64UrlDecoder;
import static ch.csnc.burp.jwtscanner.Base64.base64UrlEncoderNoPadding;
import static ch.csnc.burp.jwtscanner.Gson.gson;

/**
 * JSON Web Key
 */
public class Jwk {

    private final LinkedHashMap<String, Object> keyValues = new LinkedHashMap<>();

    public Jwk(String kid, RSAPublicKey publicKey) {
        keyValues.put("kid", kid);
        keyValues.put("kty", "RSA");
        keyValues.put("e", base64UrlEncoderNoPadding.encodeToString(publicKey.getPublicExponent().toByteArray()));
        keyValues.put("n", base64UrlEncoderNoPadding.encodeToString(publicKey.getModulus().toByteArray()));
    }

    Jwk(Map<String, Object> keyValues) {
        this.keyValues.putAll(keyValues);
    }

    public String kid() {
        return (String) keyValues.get("kid");
    }

    /**
     * @return exponent base64 url encoded (no padding)
     */
    public String exponent() {
        return (String) keyValues.get("e");
    }

    public BigInteger exponentBigInt() {
        return new BigInteger(1, base64UrlDecoder.decode(exponent()));
    }

    /**
     * @return modulus base64 url encoded (no padding)
     */
    public String modulus() {
        return (String) keyValues.get("n");
    }

    public BigInteger modulusBigInt() {
        return new BigInteger(1, base64UrlDecoder.decode(modulus()));
    }

    public static class JwkJsonSerializer implements JsonSerializer<Jwk> {

        @Override
        public JsonElement serialize(Jwk src, Type typeOfSrc, JsonSerializationContext context) {
            return gson.toJsonTree(src.keyValues);
        }

    }

    public static class JwkJsonDeserializer implements JsonDeserializer<Jwk> {

        @Override
        @SuppressWarnings("unchecked")
        public Jwk deserialize(JsonElement json, Type typeOfT, JsonDeserializationContext context) throws JsonParseException {
            var keyValues = gson.fromJson(json, LinkedHashMap.class);
            return new Jwk(keyValues);
        }

    }

    @Override
    public String toString() {
        return gson.toJson(this);
    }

}
