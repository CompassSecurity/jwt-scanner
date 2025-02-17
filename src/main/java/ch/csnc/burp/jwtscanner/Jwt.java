package ch.csnc.burp.jwtscanner;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.ToNumberPolicy;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import java.math.BigDecimal;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;
import java.util.regex.Pattern;

/**
 * This class is designed to be immutable, meaning that its internal state should not be altered by any method calls.
 * Instead, new {@link Jwt} instances should be returned.
 * <p>
 * This class uses {@link LinkedHashMap} as the underlying data structure when decoding and encoding JSON strings.
 * This preserves the order of key insertion, which is important for producing JSON strings with a consistent key order.
 * While this may not be critical for JSON itself, it is essential for JWT, as an inconsistent key order can lead to
 * signature mismatches.
 */
public class Jwt {

    @FunctionalInterface
    interface TriConsumer<A, B, C> {
        void accept(A a, B b, C c);
    }

    public static final Pattern PATTERN = Pattern.compile("(ey[a-zA-Z0-9_=]+)\\.(ey[a-zA-Z0-9_=\\-]+)\\.([a-zA-Z0-9_\\-+/=]*)");

    private static final Base64.Encoder base64UrlEncoder = Base64.getUrlEncoder().withoutPadding();
    private static final Base64.Decoder base64UrlDecoder = Base64.getUrlDecoder();

    private static final Gson gson = new GsonBuilder().setObjectToNumberStrategy(ToNumberPolicy.BIG_DECIMAL).create();

    private LinkedHashMap<String, Object> header;
    private LinkedHashMap<String, Object> payload;
    private String signature;

    @SuppressWarnings("unchecked")
    private static void decode(String encodedJwt, TriConsumer<LinkedHashMap<String, Object>, LinkedHashMap<String, Object>, String> consumer) {
        var parts = encodedJwt.split("\\.", -1);
        if (parts.length != 3) {
            throw new IllegalArgumentException("parse error: %s".formatted(encodedJwt));
        }
        var headerBytes = base64UrlDecoder.decode(parts[0]);
        var payloadBytes = base64UrlDecoder.decode(parts[1]);
        var headerString = new String(headerBytes, StandardCharsets.UTF_8);
        var payloadString = new String(payloadBytes, StandardCharsets.UTF_8);
        var header = gson.fromJson(headerString, LinkedHashMap.class);
        var payload = gson.fromJson(payloadString, LinkedHashMap.class);
        var signature = parts[2];
        consumer.accept(header, payload, signature);
    }


    private static String encode(LinkedHashMap<String, Object> header, LinkedHashMap<String, Object> payload) {
        var headerJson = gson.toJson(header);
        var headerBase64 = base64UrlEncoder.encodeToString(headerJson.getBytes(StandardCharsets.UTF_8));
        var payloadJson = gson.toJson(payload);
        var payloadBase64 = base64UrlEncoder.encodeToString(payloadJson.getBytes(StandardCharsets.UTF_8));
        return "%s.%s".formatted(headerBase64, payloadBase64);
    }

    private static String encode(LinkedHashMap<String, Object> header, LinkedHashMap<String, Object> payload, String signature) {
        return "%s.%s".formatted(encode(header, payload), signature);
    }

    public Jwt(String encodedJwt) {
        decode(encodedJwt, (header, payload, signature) -> {
            this.header = header;
            this.payload = payload;
            this.signature = signature;
        });
    }

    public String encode() {
        return encode(this.header, this.payload, this.signature);
    }

    public boolean hasExpiry() {
        return this.payload.containsKey("exp");
    }

    public boolean isExpired() {
        if (this.hasExpiry()) {
            var exp = (BigDecimal) this.payload.get("exp");
            var now = System.currentTimeMillis() / 1000;
            return exp.longValue() < now;
        }
        return false;
    }

    public Jwt withRemovedSignature() {
        return new Jwt.Builder(this).withSignature("").build();
    }

    public Jwt withWrongSignature() {
        var chars = Arrays.asList(this.signature.split(""));
        Collections.shuffle(chars);
        var signature = String.join("", chars);
        return new Jwt.Builder(this).withSignature(signature).build();
    }

    public List<Jwt> withAlgNone() {
        var input = "none";
        var permutations = new ArrayList<String>();
        int n = input.length();
        int totalPermutations = 1 << n; // 2^n permutations
        for (int i = 0; i < totalPermutations; i++) {
            char[] perm = input.toCharArray();
            for (int j = 0; j < n; j++) {
                if ((i & (1 << j)) != 0) {
                    perm[j] = Character.toUpperCase(perm[j]);
                }
            }
            permutations.add(new String(perm));
        }
        return permutations.stream().map(alg -> new Jwt.Builder(this).withHeader("alg", alg).withSignature("").build()).toList();
    }

    public Jwt withEmptyPassword() {
        return new Jwt.Builder(this).withHeader("alg", "HS256").withHS256Signature("").build();
    }

    public Jwt withInvalidEcdsa() {
        // CVE-2022-21449
        return new Jwt.Builder(this).withHeader("alg", "ES256").withSignature("MAYCAQACAQA").build();
    }

    public Jwt withInjectedJwkSelfSigned() {
        try {
            var privateKeyEncoded = JwtScannerExtension.apiAdapter().persistence().extensionData().getByteArray("privatekey");
            var publicKeyEncoded = JwtScannerExtension.apiAdapter().persistence().extensionData().getByteArray("publickey");
            if (privateKeyEncoded == null || publicKeyEncoded == null) {
                var keyPairGen = KeyPairGenerator.getInstance("RSA");
                keyPairGen.initialize(2048);
                var keyPair = keyPairGen.generateKeyPair();
                privateKeyEncoded = keyPair.getPrivate().getEncoded();
                publicKeyEncoded = keyPair.getPublic().getEncoded();
                JwtScannerExtension.apiAdapter().persistence().extensionData().setByteArray("privatekey", privateKeyEncoded);
                JwtScannerExtension.apiAdapter().persistence().extensionData().setByteArray("publickey", publicKeyEncoded);
            }
            var keyFactory = KeyFactory.getInstance("RSA");
            var privateKey = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(privateKeyEncoded));
            var publicKey = (RSAPublicKey) keyFactory.generatePublic(new X509EncodedKeySpec(publicKeyEncoded));
            var kid = UUID.randomUUID().toString();
            var jwk = new LinkedHashMap<String, Object>();
            jwk.put("kid", kid);
            jwk.put("kty", "RSA");
            jwk.put("e", base64UrlEncoder.encodeToString(publicKey.getPublicExponent().toByteArray()));
            jwk.put("n", base64UrlEncoder.encodeToString(publicKey.getModulus().toByteArray()));
            return new Jwt.Builder(this).withHeader("alg", "RS256").withHeader("kid", kid).withHeader("jwk", jwk).withRS256Signature(privateKey).build();
        } catch (Exception exc) {
            JwtScannerExtension.apiAdapter().logging().logToError(exc);
            throw new RuntimeException(exc);
        }
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        Jwt jwt = (Jwt) o;
        return Objects.equals(header, jwt.header) && Objects.equals(payload, jwt.payload) && Objects.equals(signature, jwt.signature);
    }

    @Override
    public int hashCode() {
        return Objects.hash(header, payload, signature);
    }

    @Override
    public String toString() {
        return this.encode();
    }

    public static Builder newBuilder() {
        return new Builder();
    }

    public static Builder newBuilder(String encodedJwt) {
        return new Builder(encodedJwt);
    }

    public static class Builder {

        private LinkedHashMap<String, Object> header;
        private LinkedHashMap<String, Object> payload;
        private String signature;

        private Builder() {
            this.header = new LinkedHashMap<>();
            this.payload = new LinkedHashMap<>();
            this.signature = "";
        }

        private Builder(String encodedJwt) {
            decode(encodedJwt, (header, payload, signature) -> {
                this.header = header;
                this.payload = payload;
                this.signature = signature;
            });
        }

        public Builder(Jwt jwt) {
            this(jwt.encode());
        }

        public Builder withHeader(String key, Object value) {
            this.header.put(key, value);
            return this;
        }

        public Builder withClaim(String key, Object value) {
            this.payload.put(key, value);
            return this;
        }

        public Builder withSignature(String signature) {
            this.signature = signature;
            return this;
        }

        public Builder withHS256Signature(String secret) {
            try {
                var headerPayload = encode(this.header, this.payload);
                var secretKeySpec = new SecretKey() {
                    @Override
                    public String getAlgorithm() {
                        return "HmacSHA256";
                    }

                    @Override
                    public String getFormat() {
                        return "RAW";
                    }

                    @Override
                    public byte[] getEncoded() {
                        return secret.getBytes(StandardCharsets.UTF_8);
                    }
                };
                var mac = Mac.getInstance("HmacSHA256");
                mac.init(secretKeySpec);
                var signatureBytes = mac.doFinal(headerPayload.getBytes(StandardCharsets.UTF_8));
                this.signature = base64UrlEncoder.encodeToString(signatureBytes);
                return this;
            } catch (Exception exc) {
                JwtScannerExtension.apiAdapter().logging().logToError(exc);
                throw new RuntimeException(exc);
            }
        }

        public Builder withRS256Signature(PrivateKey privateKey) {
            try {
                var headerPayload = encode(this.header, this.payload);
                var signer = Signature.getInstance("SHA256withRSA");
                signer.initSign(privateKey);
                signer.update(headerPayload.getBytes(StandardCharsets.UTF_8));
                this.signature = base64UrlEncoder.encodeToString(signer.sign());
                return this;
            } catch (Exception exc) {
                JwtScannerExtension.apiAdapter().logging().logToError(exc);
                throw new RuntimeException(exc);
            }
        }

        public Jwt build() {
            // It may seem inefficient to encode the header, payload, and signature, which are
            // decoded again in the Jwt constructor. However, this is done intentionally to ensure
            // that all data is copied and that no data structures are passed by reference,
            // which would make the Jwt class mutable. Note that Map.copyOf does not perform deep copies.
            return new Jwt(encode(this.header, this.payload, signature));
        }

    }
}
