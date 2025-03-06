package ch.csnc.burp.jwtscanner;

import java.security.KeyPair;
import java.security.interfaces.RSAPublicKey;
import java.util.List;
import java.util.Optional;

/**
 * Temporary data store for this extension
 */
public class Storage {

    private Jwk jwk;
    private List<RSAPublicKey> forgedPublicKeys;
    private RSAPublicKey publicKeyForAlgConfusion;
    private KeyPair generatedKeyPair;

    public Jwk putJwk(Jwk jwk) {
        this.jwk = jwk;
        return jwk;
    }

    public Optional<Jwk> getJwk() {
        return Optional.ofNullable(this.jwk);
    }

    public List<RSAPublicKey> putForgedPublicKeys(List<RSAPublicKey> publicKeys) {
        this.forgedPublicKeys = List.copyOf(publicKeys);
        return publicKeys;
    }

    public List<RSAPublicKey> getForgedPublicKeys() {
        if (this.forgedPublicKeys == null) {
            return List.of();
        }
        return List.copyOf(this.forgedPublicKeys);
    }

    public RSAPublicKey putPublicKeyForAlgConfusion(RSAPublicKey publicKeyForAlgConfusion) {
        this.publicKeyForAlgConfusion = publicKeyForAlgConfusion;
        return publicKeyForAlgConfusion;
    }

    public Optional<RSAPublicKey> getPublicKeyForAlgConfusion() {
        return Optional.ofNullable(this.publicKeyForAlgConfusion);
    }

    public KeyPair putGeneratedKeyPair(KeyPair generatedKeyPair) {
        this.generatedKeyPair = generatedKeyPair;
        return generatedKeyPair;
    }

    public Optional<KeyPair> getGeneratedKeyPair() {
        return Optional.ofNullable(this.generatedKeyPair);
    }

}
