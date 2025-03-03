package ch.csnc.burp.jwtscanner;

import static java.util.Base64.*;

public abstract class Base64 {

    public static final Encoder base64EncoderWithPadding = getEncoder();
    public static final Encoder base64UrlEncoderWithPadding = getUrlEncoder();
    public static final Encoder base64UrlEncoderNoPadding = getUrlEncoder().withoutPadding();
    public static final Decoder base64UrlDecoder = getUrlDecoder();

}
