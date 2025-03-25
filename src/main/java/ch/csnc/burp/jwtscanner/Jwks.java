package ch.csnc.burp.jwtscanner;

import java.util.List;
import java.util.Optional;

/**
 * JSON Web Key Set
 */
public class Jwks {

    private final List<Jwk> keys;

    public Jwks(Jwk... jwks) {
        this.keys = List.of(jwks);
    }

    public Jwks(List<Jwk> jwks) {
        this.keys = List.copyOf(jwks);
    }

    public List<Jwk> keys() {
        return List.copyOf(this.keys);
    }

    public Optional<Jwk> forKid(String kid) {
        return this.keys.stream()
                .filter(jwk -> kid.equals(jwk.kid()))
                .findFirst();
    }

}
