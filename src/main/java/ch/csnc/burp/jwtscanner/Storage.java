package ch.csnc.burp.jwtscanner;

import java.security.interfaces.RSAPublicKey;
import java.util.List;
import java.util.Optional;

/**
 * Temporary data store for this extension
 */
public class Storage {

    private Jwk jwk;
    private List<RSAPublicKey> forgedPublicKeys;

    public void putJwk(Jwk jwk) {
        this.jwk = jwk;
    }

    public Optional<Jwk> getJwk() {
        return Optional.ofNullable(this.jwk);
    }

    public void putForgedPublicKeys(List<RSAPublicKey> publicKeys) {
        this.forgedPublicKeys = List.copyOf(publicKeys);
    }

    public List<RSAPublicKey> getForgedPublicKeys() {
        return List.copyOf(this.forgedPublicKeys);
    }

}
