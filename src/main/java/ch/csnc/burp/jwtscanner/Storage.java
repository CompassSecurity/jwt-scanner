package ch.csnc.burp.jwtscanner;

import java.util.Optional;

/**
 * Temporary data store for this extension
 */
public class Storage {

    private Jwk jwk;

    public void putJwk(Jwk jwk) {
        this.jwk = jwk;
    }

    public Optional<Jwk> getJwk() {
        return Optional.ofNullable(this.jwk);
    }

}
