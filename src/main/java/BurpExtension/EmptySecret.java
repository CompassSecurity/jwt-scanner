package BurpExtension;

import javax.crypto.SecretKey;

public class EmptySecret implements SecretKey {

    @Override
    public String getAlgorithm() {
        return "HMAC";
    }

    @Override
    public String getFormat() {
        return "RAW";
    }

    @Override
    public byte[] getEncoded() {

        // return empty key data
        return new byte[0];
    }
}
